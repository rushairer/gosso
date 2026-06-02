package controller

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/rushairer/gosso/internal/auth/middleware"
	oauth2Domain "github.com/rushairer/gosso/internal/oauth2/domain"
	oauth2Service "github.com/rushairer/gosso/internal/oauth2/service"
	oidcService "github.com/rushairer/gosso/internal/oidc/service"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
)

// TokenManager defines the token operations needed by the OAuth2 controller.
type TokenManager interface {
	GenerateAccessToken(claims *tokenDomain.AccessTokenClaims) (string, error)
	GenerateRefreshToken(ctx context.Context, accountID, clientID, sessionID, scope string) (*tokenDomain.RefreshToken, error)
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
	MarkUsed(ctx context.Context, deviceCode string) error
	ClaimAuthorizedDeviceCode(ctx context.Context, deviceCode string) (*oauth2Domain.DeviceCode, error)
}

//go:embed template/consent.html
var consentTemplateFS embed.FS

//go:embed template/device.html
var deviceTemplateFS embed.FS

// OAuth2Controller handles OAuth2 protocol endpoints.
type OAuth2Controller struct {
	clientSvc     oauth2Service.OAuth2ClientService
	authCodeSvc   *oauth2Service.AuthCodeService
	consentSvc    *oauth2Service.ConsentService
	tokenSvc      TokenManager
	idTokenSvc    *oidcService.IDTokenService
	deviceCodeSvc DeviceCodeManager
	issuer        string
	consentTmpl   *template.Template
	deviceTmpl    *template.Template
	logger        *zap.Logger
}

// NewOAuth2Controller creates a new OAuth2 controller instance.
func NewOAuth2Controller(
	clientSvc oauth2Service.OAuth2ClientService,
	authCodeSvc *oauth2Service.AuthCodeService,
	consentSvc *oauth2Service.ConsentService,
	tokenSvc TokenManager,
	idTokenSvc *oidcService.IDTokenService,
	deviceCodeSvc DeviceCodeManager,
	issuer string,
	logger *zap.Logger,
) *OAuth2Controller {
	consentTmpl, err := template.ParseFS(consentTemplateFS, "template/consent.html")
	if err != nil {
		panic("failed to parse consent template: " + err.Error())
	}
	deviceTmpl, err := template.ParseFS(deviceTemplateFS, "template/device.html")
	if err != nil {
		panic("failed to parse device template: " + err.Error())
	}
	return &OAuth2Controller{
		clientSvc:     clientSvc,
		authCodeSvc:   authCodeSvc,
		consentSvc:    consentSvc,
		tokenSvc:      tokenSvc,
		idTokenSvc:    idTokenSvc,
		deviceCodeSvc: deviceCodeSvc,
		issuer:        issuer,
		consentTmpl:   consentTmpl,
		deviceTmpl:    deviceTmpl,
		logger:        logger,
	}
}

// RegisterRoutes registers OAuth2 routes.
func (c *OAuth2Controller) RegisterRoutes(server *gin.Engine, authMiddleware gin.HandlerFunc) {
	oauth2 := server.Group("/oauth2")
	{
		oauth2.GET("/authorize", authMiddleware, c.Authorize)
		oauth2.POST("/authorize", authMiddleware, c.SubmitConsent)
		oauth2.POST("/token", c.Token)
		oauth2.POST("/revoke", authMiddleware, c.Revoke)
		oauth2.POST("/introspect", c.Introspect)
		oauth2.POST("/device/code", c.DeviceCodeRequest)
		oauth2.GET("/device", authMiddleware, c.DeviceUserPage)
		oauth2.POST("/device", authMiddleware, c.DeviceUserSubmit)
	}
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

	existingConsent, _ := c.consentSvc.GetConsent(ctx, accountIDStr, clientID)
	if existingConsent != nil {
		// Only grant scopes the user previously consented to
		requestedScopes := splitScope(scope)
		allowedScopes := intersectScopes(requestedScopes, existingConsent.Scopes)
		if len(allowedScopes) == 0 {
			// No overlap — require re-consent
			ctx.Header("Content-Type", "text/html; charset=utf-8")
			_ = c.consentTmpl.Execute(ctx.Writer, gin.H{
				"ClientName": client.Name, "ClientID": clientID,
				"Scopes": requestedScopes, "Scope": scope, "State": state,
				"RedirectURI": redirectURI, "CodeChallenge": codeChallenge,
				"CodeChallengeMethod": codeChallengeMethod, "Nonce": nonce,
			})
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

	ctx.Header("Content-Type", "text/html; charset=utf-8")

	_ = c.consentTmpl.Execute(ctx.Writer, gin.H{
		"ClientName":          client.Name,
		"ClientID":            clientID,
		"Scopes":              splitScope(scope),
		"Scope":               scope,
		"State":               state,
		"RedirectURI":         redirectURI,
		"CodeChallenge":       codeChallenge,
		"CodeChallengeMethod": codeChallengeMethod,
		"Nonce":               nonce,
	})
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

	if !req.Approved {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "consent_denied"})
		return
	}

	scopes := splitScope(req.Scope)

	_ = c.consentSvc.SaveConsent(ctx, &oauth2Domain.Consent{
		AccountID: accountIDStr,
		ClientID:  req.ClientID,
		Scopes:    scopes,
	})

	code, err := c.authCodeSvc.GenerateCode(ctx, req.ClientID, accountIDStr, req.RedirectURI, scopes, req.CodeChallenge, req.CodeChallengeMethod, req.Nonce)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	redirectWithCode(ctx, req.RedirectURI, code.Code, req.State)
}

// TokenRequest is the token exchange request body.
type TokenRequest struct {
	GrantType    string `json:"grant_type" binding:"required"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	CodeVerifier string `json:"code_verifier"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	DeviceCode   string `json:"device_code"`
}

// Token POST /oauth2/token
func (c *OAuth2Controller) Token(ctx *gin.Context) {
	var req TokenRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
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

	if client.IsConfidential {
		if req.ClientSecret == "" {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "client_secret required"})
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(client.ClientSecretHash), []byte(req.ClientSecret)); err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "invalid client_secret"})
			return
		}
	} else if req.CodeVerifier == "" {
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
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": err.Error()})
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
			idToken, idErr = c.idTokenSvc.GenerateIDToken(ctx, authCode.AccountID, authCode.ClientID, authCode.Scopes, authCode.Nonce, authCode.ExpiresAt)
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
	newRefreshToken, err := c.tokenSvc.RotateRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "invalid refresh token"})
		return
	}

	// Verify client binding: if client_id is provided, it must match the token's client
	if req.ClientID != "" && req.ClientID != newRefreshToken.ClientID {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "client_id mismatch"})
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

	if err := bcrypt.CompareHashAndPassword([]byte(client.ClientSecretHash), []byte(req.ClientSecret)); err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "invalid client_secret"})
		return
	}

	scopes := client.ValidateScope(splitScope(req.Scope))
	if len(scopes) == 0 {
		scopes = client.Scopes
	}

	accessToken, err := c.tokenSvc.GenerateAccessToken(&tokenDomain.AccessTokenClaims{
		Scope:    strings.Join(scopes, " "),
		ClientID: req.ClientID,
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

	_ = c.tokenSvc.RevokeRefreshToken(ctx, req.Token)
	ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
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
	if client.IsConfidential {
		if err := bcrypt.CompareHashAndPassword([]byte(client.ClientSecretHash), []byte(clientSecret)); err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
			return
		}
	}

	result, err := c.tokenSvc.IntrospectToken(ctx, req.Token)
	if err != nil {
		ctx.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	ctx.JSON(http.StatusOK, result)
}

// DeviceCodeRequestRequest is the device code initiation request body.
type DeviceCodeRequestRequest struct {
	ClientID string `form:"client_id" binding:"required"`
	Scope    string `form:"scope"`
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

	scopes := splitScope(req.Scope)
	if len(scopes) == 0 {
		scopes = client.Scopes
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
		"verification_uri_complete": verificationURI + "?user_code=" + dc.UserCode,
		"expires_in":                int(time.Until(dc.ExpiresAt).Seconds()),
		"interval":                  dc.Interval,
	})
}

// DeviceUserPage GET /oauth2/device
func (c *OAuth2Controller) DeviceUserPage(ctx *gin.Context) {
	userCode := ctx.Query("user_code")

	if userCode == "" {
		ctx.Header("Content-Type", "text/html; charset=utf-8")
		_ = c.deviceTmpl.Execute(ctx.Writer, gin.H{
			"UserCode": "",
		})
		return
	}

	dc, err := c.deviceCodeSvc.GetDeviceCodeByUserCode(ctx, userCode)
	if err != nil {
		ctx.Header("Content-Type", "text/html; charset=utf-8")
		_ = c.deviceTmpl.Execute(ctx.Writer, gin.H{
			"UserCode": "",
			"Error":    "Invalid or expired code. Please try again.",
		})
		return
	}

	if dc.IsExpired() || dc.Status != oauth2Domain.DeviceCodeStatusPending {
		ctx.Header("Content-Type", "text/html; charset=utf-8")
		_ = c.deviceTmpl.Execute(ctx.Writer, gin.H{
			"UserCode": "",
			"Error":    "This code has expired or is no longer valid.",
		})
		return
	}

	client, err := c.clientSvc.FindByClientID(ctx, dc.ClientID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}

	ctx.Header("Content-Type", "text/html; charset=utf-8")
	_ = c.deviceTmpl.Execute(ctx.Writer, gin.H{
		"UserCode":   dc.UserCode,
		"DeviceCode": dc.DeviceCode,
		"ClientName": client.Name,
		"Scopes":     dc.Scopes,
	})
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

	if req.Approved == "true" {
		if err := c.deviceCodeSvc.AuthorizeDeviceCode(ctx, req.DeviceCode, accountIDStr); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
			return
		}
	} else {
		if err := c.deviceCodeSvc.DenyDeviceCode(ctx, req.DeviceCode); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
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
	if client.IsConfidential {
		if req.ClientSecret == "" {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "client_secret required"})
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(client.ClientSecretHash), []byte(req.ClientSecret)); err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "invalid client_secret"})
			return
		}
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

	switch dc.Status {
	case oauth2Domain.DeviceCodeStatusPending:
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "authorization_pending", "error_description": "user has not yet authorized the device"})
		return
	case oauth2Domain.DeviceCodeStatusDenied:
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "access_denied", "error_description": "user denied the authorization request"})
		return
	case oauth2Domain.DeviceCodeStatusUsed:
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "device code already used"})
		return
	}

	// Atomically claim the device code (status authorized→used) to prevent double-use
	claimedDC, err := c.deviceCodeSvc.ClaimAuthorizedDeviceCode(ctx, req.DeviceCode)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "device code already consumed"})
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
				idToken, _ = c.idTokenSvc.GenerateIDToken(ctx, dc.AccountID, dc.ClientID, dc.Scopes, "", time.Now().Add(c.tokenSvc.AccessExpiry()))
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
	params := url.Values{}
	params.Set("code", code)
	if state != "" {
		params.Set("state", state)
	}
	ctx.Redirect(http.StatusFound, redirectURI+"?"+params.Encode())
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