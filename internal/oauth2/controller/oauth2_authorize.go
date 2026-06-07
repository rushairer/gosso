package controller

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/middleware"
	oauth2Domain "github.com/rushairer/gosso/internal/oauth2/domain"
)

const consentStateTTL = 10 * time.Minute
const consentStateKeyPrefix = "consent_state:"

// consentState stores the PKCE and authorization parameters from the GET /authorize request.
// It is persisted in Redis to prevent tampering between the consent page render and the POST.
type consentState struct {
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	Nonce               string `json:"nonce"`
}

// Authorize GET /oauth2/authorize
func (c *OAuth2Controller) Authorize(ctx *gin.Context) {
	clientID := ctx.Query("client_id")
	redirectURI := ctx.Query("redirect_uri")
	responseType := ctx.Query("response_type")
	scope := ctx.Query("scope")
	state := ctx.Query("state")
	codeChallenge := ctx.Query("code_challenge")
	codeChallengeMethod := ctx.Query("code_challenge_method")
	nonce := ctx.Query("nonce")

	if codeChallenge != "" && codeChallengeMethod != "S256" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "code_challenge_method must be S256"})
		return
	}

	if responseType != "code" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_response_type"})
		return
	}

	client, err := c.clientSvc.FindByClientID(ctx, clientID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}

	if !client.ValidateRedirectURI(redirectURI) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_redirect_uri"})
		return
	}

	// PKCE is mandatory for public clients (RFC 7636 Section 4.1)
	if !client.IsConfidential && codeChallenge == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "code_challenge is required for public clients"})
		return
	}

	accountIDStr, ok := middleware.GetAccountID(ctx)
	if !ok {
		return
	}

	// Store PKCE + nonce parameters server-side to prevent tampering in the consent form.
	consentID := uuid.New().String()
	if c.redis != nil {
		stateData, _ := json.Marshal(consentState{
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			Nonce:               nonce,
		})
		if err := c.redis.Set(ctx, consentStateKeyPrefix+consentID, string(stateData), consentStateTTL); err != nil {
			c.logger.Warn("Failed to store consent state, falling back to form-only", zap.Error(err))
			consentID = ""
		}
	}

	existingConsent, consentErr := c.consentSvc.GetConsent(ctx, accountIDStr, clientID)
	if consentErr != nil {
		c.logger.Warn("Failed to get consent, showing consent page", zap.Error(consentErr), zap.String("account_id", accountIDStr), zap.String("client_id", clientID))
	}
	if existingConsent != nil {
		// Only grant scopes the user previously consented to AND the client is currently allowed
		requestedScopes := splitScope(scope)
		clientAllowedScopes := client.ValidateScope(requestedScopes)
		allowedScopes := intersectScopes(clientAllowedScopes, existingConsent.Scopes)
		if len(allowedScopes) == 0 {
			// No overlap — require re-consent
			var buf bytes.Buffer
			if err := c.consentTmpl.Execute(&buf, gin.H{
				"ClientName": client.Name, "ClientID": clientID,
				"Scopes": requestedScopes, "Scope": scope, "State": state,
				"RedirectURI": redirectURI, "CodeChallenge": codeChallenge,
				"CodeChallengeMethod": codeChallengeMethod, "Nonce": nonce,
				"CSRFToken": csrfTokenFromCookie(ctx), "ConsentID": consentID,
			}); err != nil {
				c.logger.Error("Failed to render consent template", zap.Error(err))
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
				return
			}
			ctx.Data(http.StatusOK, "text/html; charset=utf-8", buf.Bytes())
			return
		}
		code, err := c.authCodeSvc.GenerateCode(ctx, clientID, accountIDStr, redirectURI, allowedScopes, codeChallenge, codeChallengeMethod, nonce)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}
		redirectWithCode(ctx, redirectURI, code.Code, state)
		return
	}

	var buf bytes.Buffer
	if err := c.consentTmpl.Execute(&buf, gin.H{
		"ClientName":          client.Name,
		"ClientID":            clientID,
		"Scopes":              splitScope(scope),
		"Scope":               scope,
		"State":               state,
		"RedirectURI":         redirectURI,
		"CodeChallenge":       codeChallenge,
		"CodeChallengeMethod": codeChallengeMethod,
		"Nonce":               nonce,
		"CSRFToken":           csrfTokenFromCookie(ctx),
		"ConsentID":           consentID,
	}); err != nil {
		c.logger.Error("Failed to render consent template", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	ctx.Data(http.StatusOK, "text/html; charset=utf-8", buf.Bytes())
}

// ConsentRequest is the consent approval request body.
type ConsentRequest struct {
	ClientID            string `form:"client_id" binding:"required"`
	RedirectURI         string `form:"redirect_uri" binding:"required"`
	Scope               string `form:"scope" binding:"required"`
	State               string `form:"state"`
	Approved            bool   `form:"approved"`
	CodeChallenge       string `form:"code_challenge"`
	CodeChallengeMethod string `form:"code_challenge_method"`
	Nonce               string `form:"nonce"`
	ConsentID           string `form:"consent_id"`
}

// SubmitConsent POST /oauth2/authorize
func (c *OAuth2Controller) SubmitConsent(ctx *gin.Context) {
	var req ConsentRequest
	if err := ctx.ShouldBind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	// approved is submitted via form button value
	approved := ctx.PostForm("approved")
	req.Approved = approved == "true"

	accountIDStr, ok := c.authenticateRequest(ctx)
	if !ok {
		return
	}

	if !req.Approved {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "consent_denied"})
		return
	}

	// Validate PKCE parameters against server-stored consent state to prevent tampering.
	if c.redis != nil && req.ConsentID != "" {
		stateKey := consentStateKeyPrefix + req.ConsentID
		stateData, err := c.redis.Get(ctx, stateKey)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "invalid or expired consent session"})
			return
		}
		// Delete immediately to prevent replay
		_ = c.redis.Del(ctx, stateKey)

		var stored consentState
		if err := json.Unmarshal([]byte(stateData), &stored); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "invalid consent session data"})
			return
		}
		if req.CodeChallenge != stored.CodeChallenge ||
			req.CodeChallengeMethod != stored.CodeChallengeMethod ||
			req.Nonce != stored.Nonce {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "PKCE parameters mismatch"})
			return
		}
	}

	// Validate client exists
	client, err := c.clientSvc.FindByClientID(ctx, req.ClientID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}

	// Validate redirect URI against client registration (prevents open redirect)
	if !client.ValidateRedirectURI(req.RedirectURI) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_redirect_uri"})
		return
	}

	scopes := splitScope(req.Scope)

	// Validate scopes against client registration
	scopes = client.ValidateScope(scopes)
	if len(scopes) == 0 {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_scope"})
		return
	}

	if err := c.consentSvc.SaveConsent(ctx, &oauth2Domain.Consent{
		AccountID: accountIDStr,
		ClientID:  req.ClientID,
		Scopes:    scopes,
	}); err != nil {
		c.logger.Error("Failed to save consent", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	code, err := c.authCodeSvc.GenerateCode(ctx, req.ClientID, accountIDStr, req.RedirectURI, scopes, req.CodeChallenge, req.CodeChallengeMethod, req.Nonce)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	redirectWithCode(ctx, req.RedirectURI, code.Code, req.State)
}
