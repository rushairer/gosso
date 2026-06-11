package controller

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	oauth2Domain "github.com/rushairer/gosso/internal/oauth2/domain"
	"github.com/rushairer/gosso/middleware"
)

const consentStateTTL = 10 * time.Minute
const consentStateKeyPrefix = "consent_state:"

// getAndDeleteConsentScript atomically retrieves and deletes consent state from Redis.
// This prevents replay attacks where a concurrent request reads the same consent state
// before it is deleted.
var getAndDeleteConsentScript = redis.NewScript(`
local data = redis.call('GET', KEYS[1])
if data then
    redis.call('DEL', KEYS[1])
end
return data
`)

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

	// State parameter is required for public clients (RFC 6749 Section 10.12)
	if !client.IsConfidential && state == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "state parameter is required for public clients"})
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

	// Verify the account is still active — suspended accounts must not generate authorization codes.
	if !c.accountValidator.IsAccountActive(ctx, accountIDStr) {
		ctx.JSON(http.StatusForbidden, gin.H{"error": "access_denied", "error_description": "account is not active"})
		return
	}

	// Store PKCE + nonce parameters server-side to prevent tampering in the consent form.
	// Redis is required for consent state storage; reject if unavailable to prevent PKCE bypass.
	consentID := uuid.New().String()
	if c.redis == nil {
		ctx.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             "server_error",
			"error_description": "consent state storage unavailable",
		})
		return
	}
	stateData, err := json.Marshal(consentState{
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Nonce:               nonce,
	})
	if err != nil {
		c.logger.Error("Failed to marshal consent state", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error": "server_error",
		})
		return
	}
	if err := c.redis.Set(ctx, consentStateKeyPrefix+consentID, string(stateData), consentStateTTL); err != nil {
		c.logger.Error("Failed to store consent state in Redis", zap.Error(err))
		ctx.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             "server_error",
			"error_description": "unable to process consent, please try again",
		})
		return
	}

	existingConsent, consentErr := c.consentSvc.GetConsent(ctx, accountIDStr, clientID)
	if consentErr != nil && !errors.Is(consentErr, oauth2Domain.ErrConsentNotFound) {
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
				"CSPNonce": middleware.GetCSPNonce(ctx),
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
		"CSPNonce":            middleware.GetCSPNonce(ctx),
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

	// Validate CSRF token (double-submit cookie pattern).
	// Skip for Bearer-authenticated requests — JWT tokens are not affected by CSRF.
	authHeader := ctx.GetHeader("Authorization")
	isBearerAuth := strings.HasPrefix(authHeader, "Bearer ") && len(authHeader) > 7
	if !isBearerAuth {
		cookieToken := csrfTokenFromCookie(ctx)
		formToken := ctx.PostForm("csrf_token")
		if cookieToken == "" || formToken == "" || subtle.ConstantTimeCompare([]byte(cookieToken), []byte(formToken)) != 1 {
			ctx.JSON(http.StatusForbidden, gin.H{"error": "invalid_csrf", "error_description": "CSRF token mismatch"})
			return
		}
	}

	// approved is submitted via form button value
	approved := ctx.PostForm("approved")
	req.Approved = approved == "true"

	accountIDStr, ok := c.authenticateRequest(ctx)
	if !ok {
		return
	}

	if !req.Approved {
		// Validate redirect_uri against client registration before redirecting
		client, clientErr := c.clientSvc.FindByClientID(ctx, req.ClientID)
		if clientErr != nil || !client.ValidateRedirectURI(req.RedirectURI) {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client", "error_description": "invalid client or redirect_uri"})
			return
		}
		redirectURI := req.RedirectURI
		if req.State != "" {
			u, err := url.Parse(redirectURI)
			if err == nil {
				q := u.Query()
				q.Set("error", "access_denied")
				q.Set("state", req.State)
				u.RawQuery = q.Encode()
				redirectURI = u.String()
			}
		} else {
			redirectURI += "?error=access_denied"
		}
		ctx.Redirect(http.StatusFound, redirectURI)
		return
	}

	// Validate PKCE parameters against server-stored consent state to prevent tampering.
	// Consent ID is mandatory because Authorize always stores state in Redis.
	if req.ConsentID == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "missing consent session"})
		return
	}
	if c.redis == nil {
		ctx.JSON(http.StatusServiceUnavailable, gin.H{"error": "server_error", "error_description": "consent state storage unavailable"})
		return
	}
	stateKey := consentStateKeyPrefix + req.ConsentID
	stateDataRaw, err := c.redis.RunScript(ctx, getAndDeleteConsentScript, []string{stateKey}).Result()
	if err != nil && err != redis.Nil {
		ctx.JSON(http.StatusServiceUnavailable, gin.H{"error": "server_error", "error_description": "consent state storage error"})
		return
	}
	stateData, _ := stateDataRaw.(string)
	if stateData == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "invalid or expired consent session"})
		return
	}

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
