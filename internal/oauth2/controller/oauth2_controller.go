package controller

import (
	"context"
	"embed"
	"html/template"
	"net/http"
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

//go:embed template/consent.html
var consentTemplateFS embed.FS

// OAuth2Controller handles OAuth2 protocol endpoints.
type OAuth2Controller struct {
	clientSvc   oauth2Service.OAuth2ClientService
	authCodeSvc *oauth2Service.AuthCodeService
	consentSvc  *oauth2Service.ConsentService
	tokenSvc    TokenManager
	idTokenSvc  *oidcService.IDTokenService
	consentTmpl *template.Template
	logger      *zap.Logger
}

// NewOAuth2Controller creates a new OAuth2 controller instance.
func NewOAuth2Controller(
	clientSvc oauth2Service.OAuth2ClientService,
	authCodeSvc *oauth2Service.AuthCodeService,
	consentSvc *oauth2Service.ConsentService,
	tokenSvc TokenManager,
	idTokenSvc *oidcService.IDTokenService,
	logger *zap.Logger,
) *OAuth2Controller {
	tmpl, err := template.ParseFS(consentTemplateFS, "template/consent.html")
	if err != nil {
		panic("failed to parse consent template: " + err.Error())
	}
	return &OAuth2Controller{
		clientSvc:   clientSvc,
		authCodeSvc: authCodeSvc,
		consentSvc:  consentSvc,
		tokenSvc:    tokenSvc,
		idTokenSvc:  idTokenSvc,
		consentTmpl: tmpl,
		logger:      logger,
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
		code, err := c.authCodeSvc.GenerateCode(ctx, clientID, accountIDStr, redirectURI, splitScope(scope), codeChallenge, codeChallengeMethod, nonce)
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
			idToken, _ = c.idTokenSvc.GenerateIDToken(ctx, authCode.AccountID, authCode.ClientID, authCode.Scopes, authCode.Nonce, authCode.ExpiresAt)
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

func redirectWithCode(ctx *gin.Context, redirectURI, code, state string) {
	url := redirectURI + "?code=" + code
	if state != "" {
		url += "&state=" + state
	}
	ctx.Redirect(http.StatusFound, url)
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
