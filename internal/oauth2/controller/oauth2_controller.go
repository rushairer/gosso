package controller

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/auth/middleware"
	oauth2Domain "github.com/rushairer/gosso/internal/oauth2/domain"
	oauth2Service "github.com/rushairer/gosso/internal/oauth2/service"
	oidcService "github.com/rushairer/gosso/internal/oidc/service"
	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
)

// TokenManager defines the token operations needed by the OAuth2 controller.
type TokenManager interface {
	GenerateAccessToken(claims *tokenDomain.AccessTokenClaims) (string, error)
	GenerateRefreshToken(ctx context.Context, accountID, clientID, sessionID, scope string) (*tokenDomain.RefreshToken, error)
	ValidateRefreshToken(ctx context.Context, token string) (*tokenDomain.RefreshToken, error)
	ValidateAccessTokenWithContext(ctx context.Context, tokenString string) (*tokenDomain.AccessTokenClaims, error)
	RotateRefreshToken(ctx context.Context, oldToken string) (*tokenDomain.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, token string) error
	IntrospectToken(ctx context.Context, tokenString string) (map[string]any, error)
	AccessExpiry() time.Duration
}

// DeviceCodeManager defines the device code operations needed by the OAuth2 controller.
type DeviceCodeManager interface {
	CreateDeviceCode(ctx context.Context, clientID string, scopes []string) (*oauth2Domain.DeviceCode, error)
	GetDeviceCode(ctx context.Context, deviceCode string) (*oauth2Domain.DeviceCode, error)
	GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*oauth2Domain.DeviceCode, error)
	AuthorizeDeviceCode(ctx context.Context, deviceCode, accountID string) error
	DenyDeviceCode(ctx context.Context, deviceCode string) error
	CheckAndUpdatePollRate(ctx context.Context, deviceCode string) error
	ClaimAuthorizedDeviceCode(ctx context.Context, deviceCode string) (*oauth2Domain.DeviceCode, error)
}

// AccountValidator checks whether an account exists and is active.
type AccountValidator interface {
	IsAccountActive(ctx context.Context, accountID string) bool
}

// SessionValidator checks whether a session is still active.
type SessionValidator interface {
	ValidateSession(ctx context.Context, sessionID uuid.UUID) (*sessionDomain.Session, error)
}

//go:embed template/consent.html
var consentTemplateFS embed.FS

//go:embed template/device.html
var deviceTemplateFS embed.FS

// OAuth2Controller handles OAuth2 protocol endpoints.
type OAuth2Controller struct {
	clientSvc         oauth2Service.OAuth2ClientService
	authCodeSvc       *oauth2Service.AuthCodeService
	consentSvc        *oauth2Service.ConsentService
	tokenSvc          TokenManager
	idTokenSvc        *oidcService.IDTokenService
	deviceCodeSvc     DeviceCodeManager
	clientAuth        oauth2Service.ClientAuthenticator
	accountValidator  AccountValidator
	sessionValidator  SessionValidator
	issuer            string
	consentTmpl       *template.Template
	deviceTmpl        *template.Template
	logger            *zap.Logger
}

// NewOAuth2Controller creates a new OAuth2 controller instance.
func NewOAuth2Controller(
	clientSvc oauth2Service.OAuth2ClientService,
	authCodeSvc *oauth2Service.AuthCodeService,
	consentSvc *oauth2Service.ConsentService,
	tokenSvc TokenManager,
	idTokenSvc *oidcService.IDTokenService,
	deviceCodeSvc DeviceCodeManager,
	accountValidator AccountValidator,
	sessionValidator SessionValidator,
	issuer string,
	logger *zap.Logger,
) (*OAuth2Controller, error) {
	consentTmpl, err := template.ParseFS(consentTemplateFS, "template/consent.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse consent template: %w", err)
	}
	deviceTmpl, err := template.ParseFS(deviceTemplateFS, "template/device.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse device template: %w", err)
	}
	return &OAuth2Controller{
		clientSvc:        clientSvc,
		authCodeSvc:      authCodeSvc,
		consentSvc:       consentSvc,
		tokenSvc:         tokenSvc,
		idTokenSvc:       idTokenSvc,
		deviceCodeSvc:    deviceCodeSvc,
		clientAuth:       oauth2Service.ClientAuthenticator{},
		accountValidator: accountValidator,
		sessionValidator: sessionValidator,
		issuer:           issuer,
		consentTmpl:      consentTmpl,
		deviceTmpl:       deviceTmpl,
		logger:           logger,
	}, nil
}

// authenticateRequest extracts and validates the access token from the Authorization header.
// Returns the account ID on success, or an empty string and writes an error response on failure.
func (c *OAuth2Controller) authenticateRequest(ctx *gin.Context) (string, bool) {
	tokenString := ""
	if authHeader := ctx.GetHeader("Authorization"); authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			tokenString = parts[1]
		}
	}
	if tokenString == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return "", false
	}

	claims, err := c.tokenSvc.ValidateAccessTokenWithContext(ctx.Request.Context(), tokenString)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return "", false
	}
	if claims.Scope != "" {
		ctx.JSON(http.StatusForbidden, gin.H{"error": "forbidden", "error_description": "scoped token not allowed"})
		return "", false
	}
	if c.sessionValidator != nil && claims.SessionID != "" {
		sessionUUID, err := uuid.Parse(claims.SessionID)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return "", false
		}
		if _, err := c.sessionValidator.ValidateSession(ctx.Request.Context(), sessionUUID); err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return "", false
		}
	}
	return claims.AccountID, true
}

// RegisterRoutes registers OAuth2 routes.
// introspectLimit and deviceCodeLimit are optional rate limit middleware for CPU-intensive endpoints.
func (c *OAuth2Controller) RegisterRoutes(rg *gin.RouterGroup, authMiddleware, introspectLimit, deviceCodeLimit gin.HandlerFunc) {
	rg.GET("/authorize", authMiddleware, c.Authorize)
	rg.POST("/authorize", c.SubmitConsent)
	rg.POST("/token", c.Token)
	rg.POST("/revoke", authMiddleware, c.Revoke)

	introspectHandlers := []gin.HandlerFunc{c.Introspect}
	if introspectLimit != nil {
		introspectHandlers = []gin.HandlerFunc{introspectLimit, c.Introspect}
	}
	rg.POST("/introspect", introspectHandlers...)

	deviceCodeHandlers := []gin.HandlerFunc{c.DeviceCodeRequest}
	if deviceCodeLimit != nil {
		deviceCodeHandlers = []gin.HandlerFunc{deviceCodeLimit, c.DeviceCodeRequest}
	}
	rg.POST("/device/code", deviceCodeHandlers...)

	rg.GET("/device", authMiddleware, c.DeviceUserPage)
	rg.POST("/device", c.DeviceUserSubmit)
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

	accountID, exists := ctx.Get(middleware.ContextKeyAccountID)
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	accountIDStr, ok := accountID.(string)
	if !ok || accountIDStr == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
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
				"CSRFToken": csrfTokenFromCookie(ctx),
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

// TokenRequest is the token exchange request body.
type TokenRequest struct {
	GrantType    string `json:"grant_type" form:"grant_type" binding:"required"`
	Code         string `json:"code" form:"code"`
	RedirectURI  string `json:"redirect_uri" form:"redirect_uri"`
	ClientID     string `json:"client_id" form:"client_id"`
	ClientSecret string `json:"client_secret" form:"client_secret"`
	CodeVerifier string `json:"code_verifier" form:"code_verifier"`
	RefreshToken string `json:"refresh_token" form:"refresh_token"`
	Scope        string `json:"scope" form:"scope"`
	DeviceCode   string `json:"device_code" form:"device_code"`
}

// Token POST /oauth2/token
func (c *OAuth2Controller) Token(ctx *gin.Context) {
	var req TokenRequest
	if err := ctx.ShouldBind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	// Support client_secret_basic (RFC 6749 §2.3.1): parse Authorization: Basic header
	if clientID, clientSecret, ok := ctx.Request.BasicAuth(); ok {
		if req.ClientID == "" {
			req.ClientID = clientID
		}
		if req.ClientSecret == "" {
			req.ClientSecret = clientSecret
		}
	}

	switch req.GrantType {
	case "authorization_code":
		c.handleAuthorizationCodeGrant(ctx, &req)
	case "refresh_token":
		c.handleRefreshTokenGrant(ctx, &req)
	case "client_credentials":
		c.handleClientCredentialsGrant(ctx, &req)
	case "urn:ietf:params:oauth:grant-type:device_code":
		c.handleDeviceCodeGrant(ctx, &req)
	default:
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
	}
}

func (c *OAuth2Controller) handleAuthorizationCodeGrant(ctx *gin.Context, req *TokenRequest) {
	client, err := c.clientSvc.FindByClientID(ctx, req.ClientID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}

	if !client.HasGrantType("authorization_code") {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "unauthorized_client", "error_description": "client is not authorized for authorization_code grant"})
		return
	}

	if err := c.clientAuth.AuthenticateClient(client, req.ClientSecret); err != nil {
		if errors.Is(err, oauth2Service.ErrClientSecretRequired) {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "client_secret required"})
		} else {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "invalid client_secret"})
		}
		return
	} else if !client.IsConfidential && req.CodeVerifier == "" {
		// Public clients MUST use PKCE (RFC 7636)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "code_verifier required for public clients"})
		return
	}

	var codeVerifier *string
	if req.CodeVerifier != "" {
		codeVerifier = &req.CodeVerifier
	}

	authCode, err := c.authCodeSvc.ValidateCode(ctx, req.Code, req.ClientID, req.RedirectURI, codeVerifier)
	if err != nil {
		c.logger.Debug("Authorization code validation failed", zap.Error(err))
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "invalid or expired authorization code"})
		return
	}

	if !c.accountValidator.IsAccountActive(ctx, authCode.AccountID) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "account is not active"})
		return
	}

	accessToken, err := c.tokenSvc.GenerateAccessToken(&tokenDomain.AccessTokenClaims{
		AccountID: authCode.AccountID,
		Scope:     strings.Join(authCode.Scopes, " "),
		ClientID:  authCode.ClientID,
	})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	refreshToken, err := c.tokenSvc.GenerateRefreshToken(ctx, authCode.AccountID, authCode.ClientID, "", strings.Join(authCode.Scopes, " "))
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	var idToken string
	for _, s := range authCode.Scopes {
		if s == "openid" {
			var idErr error
			idToken, idErr = c.idTokenSvc.GenerateIDToken(ctx, authCode.AccountID, authCode.ClientID, authCode.Scopes, authCode.Nonce, authCode.AuthTime)
			if idErr != nil {
				c.logger.Error("Failed to generate ID token", zap.Error(idErr))
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "failed to generate id_token"})
				return
			}
			break
		}
	}

	response := gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken.Token,
		"token_type":    "Bearer",
		"expires_in":    int(c.tokenSvc.AccessExpiry().Seconds()),
		"scope":         strings.Join(authCode.Scopes, " "),
	}
	if idToken != "" {
		response["id_token"] = idToken
	}

	ctx.JSON(http.StatusOK, response)
}

func (c *OAuth2Controller) handleRefreshTokenGrant(ctx *gin.Context, req *TokenRequest) {
	// Non-destructive read first to validate client before consuming the token
	oldRefreshToken, err := c.tokenSvc.ValidateRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "invalid refresh token"})
		return
	}

	// Verify client binding before rotation (RFC 6749 §6: client_id MUST match)
	if req.ClientID != oldRefreshToken.ClientID {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "client_id mismatch or missing"})
		return
	}

	// RFC 6749 Section 6: confidential clients MUST authenticate when using refresh token grant
	client, err := c.clientSvc.FindByClientID(ctx, oldRefreshToken.ClientID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "client not found"})
		return
	}
	if !client.HasGrantType("refresh_token") {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "unauthorized_client", "error_description": "client is not authorized for refresh_token grant"})
		return
	}
	if err := c.clientAuth.AuthenticateClient(client, req.ClientSecret); err != nil {
		if errors.Is(err, oauth2Service.ErrClientSecretRequired) {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "client_secret required for confidential clients"})
		} else {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "invalid client_secret"})
		}
		return
	}

	// Verify account is still active BEFORE consuming the old refresh token.
	// If the account is inactive, reject early so the client retains the old token.
	if !c.accountValidator.IsAccountActive(ctx, oldRefreshToken.AccountID) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "account is not active"})
		return
	}

	// RFC 6749 Section 6: requested scope must be a subset of originally granted scope
	if req.Scope != "" {
		requested := splitScope(req.Scope)
		granted := splitScope(oldRefreshToken.Scope)
		for _, s := range requested {
			if !slices.Contains(granted, s) {
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_scope", "error_description": "requested scope exceeds originally granted scope"})
				return
			}
		}
	}

	// All validations passed — now atomically rotate the token
	newRefreshToken, err := c.tokenSvc.RotateRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "invalid refresh token"})
		return
	}

	accessToken, err := c.tokenSvc.GenerateAccessToken(&tokenDomain.AccessTokenClaims{
		AccountID: newRefreshToken.AccountID,
		Scope:     newRefreshToken.Scope,
		ClientID:  newRefreshToken.ClientID,
		SessionID: newRefreshToken.SessionID,
	})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": newRefreshToken.Token,
		"token_type":    "Bearer",
		"expires_in":    int(c.tokenSvc.AccessExpiry().Seconds()),
		"scope":         newRefreshToken.Scope,
	})
}

func (c *OAuth2Controller) handleClientCredentialsGrant(ctx *gin.Context, req *TokenRequest) {
	if req.ClientID == "" || req.ClientSecret == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "client_id and client_secret required"})
		return
	}

	client, err := c.clientSvc.FindByClientID(ctx, req.ClientID)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}

	if !client.IsConfidential {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "client_credentials grant requires confidential client"})
		return
	}

	if !client.HasGrantType(oauth2Domain.GrantTypeClientCredentials) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "unauthorized_client", "error_description": "client_credentials grant not allowed"})
		return
	}

	if err := c.clientAuth.AuthenticateClient(client, req.ClientSecret); err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "invalid client_secret"})
		return
	}

	scopes := client.ValidateScope(splitScope(req.Scope))
	if len(scopes) == 0 {
		if req.Scope != "" {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_scope", "error_description": "requested scopes are not valid for this client"})
			return
		}
		scopes = client.Scopes
	}

	// Verify account is still active (deleted/suspended clients cannot get new tokens)
	if !c.accountValidator.IsAccountActive(ctx, client.AccountID) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client", "error_description": "account is not active"})
		return
	}

	accessToken, err := c.tokenSvc.GenerateAccessToken(&tokenDomain.AccessTokenClaims{
		Scope:     strings.Join(scopes, " "),
		ClientID:  req.ClientID,
		AccountID: client.AccountID,
	})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(c.tokenSvc.AccessExpiry().Seconds()),
		"scope":        strings.Join(scopes, " "),
	})
}

// Revoke POST /oauth2/revoke
func (c *OAuth2Controller) Revoke(ctx *gin.Context) {
	var req struct {
		Token string `json:"token" binding:"required"`
	}
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	// Verify the refresh token belongs to the authenticated user before revoking.
	accountID, exists := ctx.Get(middleware.ContextKeyAccountID)
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	accountIDStr, ok := accountID.(string)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	rt, err := c.tokenSvc.ValidateRefreshToken(ctx, req.Token)
	if err != nil {
		// RFC 7009 §2.1: always return 200 for invalid/unknown tokens
		// to prevent token existence oracle.
		ctx.Status(http.StatusOK)
		return
	}
	if rt.AccountID != accountIDStr {
		// Token belongs to a different user — silently skip revocation.
		ctx.Status(http.StatusOK)
		return
	}

	if err := c.tokenSvc.RevokeRefreshToken(ctx, req.Token); err != nil {
		c.logger.Error("Failed to revoke token", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	ctx.Status(http.StatusOK)
}

// IntrospectRequest is the token introspection request body.
type IntrospectRequest struct {
	Token string `json:"token" binding:"required"`
}

// Introspect POST /oauth2/introspect (RFC 7662)
func (c *OAuth2Controller) Introspect(ctx *gin.Context) {
	var req IntrospectRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	// Client authentication (Basic Auth or client_id/client_secret) - RFC 7662 requires authentication
	clientID, clientSecret, hasBasicAuth := ctx.Request.BasicAuth()
	if !hasBasicAuth {
		clientID = ctx.PostForm("client_id")
		clientSecret = ctx.PostForm("client_secret")
	}

	if clientID == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "client authentication required"})
		return
	}

	client, err := c.clientSvc.FindByClientID(ctx, clientID)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}
	if err := c.clientAuth.AuthenticateClient(client, clientSecret); err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	} else if !client.IsConfidential {
		c.logger.Warn("Introspect called by public client", zap.String("client_id", clientID))
	}

	result, err := c.tokenSvc.IntrospectToken(ctx, req.Token)
	if err != nil {
		c.logger.Error("Token introspection failed", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	// RFC 7662: only return full token info if the token belongs to the authenticated client
	if tokenClientID, ok := result["client_id"].(string); !ok || tokenClientID != clientID {
		ctx.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	ctx.JSON(http.StatusOK, result)
}

// DeviceCodeRequestRequest is the device code initiation request body.
type DeviceCodeRequestRequest struct {
	ClientID     string `form:"client_id" binding:"required"`
	ClientSecret string `form:"client_secret"`
	Scope        string `form:"scope"`
}

// DeviceCodeRequest POST /oauth2/device/code
func (c *OAuth2Controller) DeviceCodeRequest(ctx *gin.Context) {
	var req DeviceCodeRequestRequest
	if err := ctx.ShouldBind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "client_id is required"})
		return
	}

	client, err := c.clientSvc.FindByClientID(ctx, req.ClientID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}

	if !client.HasGrantType(oauth2Domain.GrantTypeDeviceCode) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "unauthorized_client", "error_description": "device_code grant not allowed"})
		return
	}

	// Client authentication for confidential clients (RFC 8628 §3.1)
	if err := c.clientAuth.AuthenticateClient(client, req.ClientSecret); err != nil {
		if errors.Is(err, oauth2Service.ErrClientSecretRequired) {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "client_secret required for confidential client"})
		} else {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "invalid client_secret"})
		}
		return
	}

	scopes := splitScope(req.Scope)
	originalScope := req.Scope
	if len(scopes) == 0 {
		scopes = client.Scopes
	} else {
		scopes = client.ValidateScope(scopes)
		if len(scopes) == 0 && originalScope != "" {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_scope", "error_description": "none of the requested scopes are valid for this client"})
			return
		}
	}

	dc, err := c.deviceCodeSvc.CreateDeviceCode(ctx, req.ClientID, scopes)
	if err != nil {
		c.logger.Error("Failed to create device code", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	verificationURI := c.issuer + "/oauth2/device"
	ctx.JSON(http.StatusOK, gin.H{
		"device_code":               dc.DeviceCode,
		"user_code":                 dc.UserCode,
		"verification_uri":          verificationURI,
		"verification_uri_complete": verificationURI + "?" + url.Values{"user_code": {dc.UserCode}}.Encode(),
		"expires_in":                int(time.Until(dc.ExpiresAt).Seconds()),
		"interval":                  dc.Interval,
	})
}

// DeviceUserPage GET /oauth2/device
func (c *OAuth2Controller) DeviceUserPage(ctx *gin.Context) {
	userCode := ctx.Query("user_code")

	if userCode == "" {
		var buf bytes.Buffer
		if err := c.deviceTmpl.Execute(&buf, gin.H{
			"UserCode": "",
		}); err != nil {
			c.logger.Error("Failed to render device template", zap.Error(err))
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}
		ctx.Data(http.StatusOK, "text/html; charset=utf-8", buf.Bytes())
		return
	}

	dc, err := c.deviceCodeSvc.GetDeviceCodeByUserCode(ctx, userCode)
	if err != nil {
		var buf bytes.Buffer
		if err := c.deviceTmpl.Execute(&buf, gin.H{
			"UserCode": "",
			"Error":    "Invalid or expired code. Please try again.",
		}); err != nil {
			c.logger.Error("Failed to render device template", zap.Error(err))
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}
		ctx.Data(http.StatusOK, "text/html; charset=utf-8", buf.Bytes())
		return
	}

	if dc.IsExpired() || dc.Status != oauth2Domain.DeviceCodeStatusPending {
		var buf bytes.Buffer
		if err := c.deviceTmpl.Execute(&buf, gin.H{
			"UserCode": "",
			"Error":    "This code has expired or is no longer valid.",
		}); err != nil {
			c.logger.Error("Failed to render device template", zap.Error(err))
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}
		ctx.Data(http.StatusOK, "text/html; charset=utf-8", buf.Bytes())
		return
	}

	client, err := c.clientSvc.FindByClientID(ctx, dc.ClientID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}

	var buf bytes.Buffer
	if err := c.deviceTmpl.Execute(&buf, gin.H{
		"UserCode":   dc.UserCode,
		"DeviceCode": dc.DeviceCode,
		"ClientName": client.Name,
		"Scopes":     dc.Scopes,
		"CSRFToken":  csrfTokenFromCookie(ctx),
	}); err != nil {
		c.logger.Error("Failed to render device template", zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	ctx.Data(http.StatusOK, "text/html; charset=utf-8", buf.Bytes())
}

// DeviceUserSubmitRequest is the device authorization form submission.
type DeviceUserSubmitRequest struct {
	DeviceCode string `form:"device_code" binding:"required"`
	UserCode   string `form:"user_code"`
	Approved   string `form:"approved"`
}

// DeviceUserSubmit POST /oauth2/device
func (c *OAuth2Controller) DeviceUserSubmit(ctx *gin.Context) {
	var req DeviceUserSubmitRequest
	if err := ctx.ShouldBind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	accountIDStr, ok := c.authenticateRequest(ctx)
	if !ok {
		return
	}

	if req.Approved == "true" {
		if err := c.deviceCodeSvc.AuthorizeDeviceCode(ctx, req.DeviceCode, accountIDStr); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "device code authorization failed"})
			return
		}
	} else {
		if err := c.deviceCodeSvc.DenyDeviceCode(ctx, req.DeviceCode); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "device code denial failed"})
			return
		}
	}

	ctx.Header("Content-Type", "text/html; charset=utf-8")
	ctx.String(http.StatusOK, "<!DOCTYPE html><html><body><p>Authorization %s. You may close this page.</p></body></html>",
		map[bool]string{true: "granted", false: "denied"}[req.Approved == "true"])
}

func (c *OAuth2Controller) handleDeviceCodeGrant(ctx *gin.Context, req *TokenRequest) {
	if req.ClientID == "" || req.DeviceCode == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "client_id and device_code required"})
		return
	}

	client, err := c.clientSvc.FindByClientID(ctx, req.ClientID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}

	if !client.HasGrantType(oauth2Domain.GrantTypeDeviceCode) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "unauthorized_client", "error_description": "device_code grant not allowed"})
		return
	}

	// Client authentication for confidential clients
	if err := c.clientAuth.AuthenticateClient(client, req.ClientSecret); err != nil {
		if errors.Is(err, oauth2Service.ErrClientSecretRequired) {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "client_secret required"})
		} else {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "invalid client_secret"})
		}
		return
	}

	dc, err := c.deviceCodeSvc.GetDeviceCode(ctx, req.DeviceCode)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "device code not found"})
		return
	}

	if dc.IsExpired() {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "expired_token", "error_description": "device code has expired"})
		return
	}

	if err := c.deviceCodeSvc.CheckAndUpdatePollRate(ctx, req.DeviceCode); err != nil {
		ctx.Header("Retry-After", fmt.Sprintf("%d", dc.Interval))
		ctx.JSON(http.StatusTooManyRequests, gin.H{"error": "slow_down", "error_description": "too many requests"})
		return
	}

	// Verify account is still active BEFORE claiming the device code.
	// If checked after claim, an inactive account would waste the device code.
	if !c.accountValidator.IsAccountActive(ctx, dc.AccountID) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "account is not active"})
		return
	}

	// Atomically claim the device code (status authorized→used) to prevent double-use.
	// The Lua script handles all status validation atomically, so no non-atomic
	// status check is needed before this call.
	claimedDC, err := c.deviceCodeSvc.ClaimAuthorizedDeviceCode(ctx, req.DeviceCode)
	if err != nil {
		// Distinguish expired vs consumed per RFC 8628 §3.5
		errorDesc := "device code already consumed"
		if lookupDC, lookupErr := c.deviceCodeSvc.GetDeviceCode(ctx, req.DeviceCode); lookupErr == nil && lookupDC.IsExpired() {
			errorDesc = "device code has expired"
		}
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": errorDesc})
		return
	}

	// Use claimedDC for token issuance
	dc = claimedDC

	accessToken, err := c.tokenSvc.GenerateAccessToken(&tokenDomain.AccessTokenClaims{
		AccountID: dc.AccountID,
		Scope:     strings.Join(dc.Scopes, " "),
		ClientID:  dc.ClientID,
	})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	refreshToken, err := c.tokenSvc.GenerateRefreshToken(ctx, dc.AccountID, dc.ClientID, "", strings.Join(dc.Scopes, " "))
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	var idToken string
	if c.idTokenSvc != nil {
		for _, s := range dc.Scopes {
			if s == "openid" {
				var idErr error
				idToken, idErr = c.idTokenSvc.GenerateIDToken(ctx, dc.AccountID, dc.ClientID, dc.Scopes, "", dc.AuthorizedAt)
				if idErr != nil {
					c.logger.Error("Failed to generate ID token for device code", zap.Error(idErr))
					ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
					return
				}
				break
			}
		}
	}

	response := gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken.Token,
		"token_type":    "Bearer",
		"expires_in":    int(c.tokenSvc.AccessExpiry().Seconds()),
		"scope":         strings.Join(dc.Scopes, " "),
	}
	if idToken != "" {
		response["id_token"] = idToken
	}

	ctx.JSON(http.StatusOK, response)
}

func redirectWithCode(ctx *gin.Context, redirectURI, code, state string) {
	parsedURL, err := url.Parse(redirectURI)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_redirect_uri"})
		return
	}
	params := parsedURL.Query()
	params.Set("code", code)
	if state != "" {
		params.Set("state", state)
	}
	parsedURL.RawQuery = params.Encode()
	ctx.Redirect(http.StatusFound, parsedURL.String())
}

func splitScope(scope string) []string {
	if scope == "" {
		return nil
	}
	var result []string
	for _, s := range strings.Split(scope, " ") {
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}

// intersectScopes returns the scopes present in both requested and allowed.
func intersectScopes(requested, allowed []string) []string {
	var result []string
	for _, s := range requested {
		if slices.Contains(allowed, s) {
			result = append(result, s)
		}
	}
	return result
}

// csrfTokenFromCookie reads the CSRF token from the request cookie for server-side template injection.
func csrfTokenFromCookie(ctx *gin.Context) string {
	cookie, _ := ctx.Cookie("csrf_token")
	return cookie
}