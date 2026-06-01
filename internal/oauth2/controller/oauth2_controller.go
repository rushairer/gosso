package controller

import (
	"embed"
	"html/template"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gosso/internal/auth/middleware"
	oauth2Domain "github.com/rushairer/gosso/internal/oauth2/domain"
	oauth2Service "github.com/rushairer/gosso/internal/oauth2/service"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	tokenService "github.com/rushairer/gosso/internal/token/service"
	oidcService "github.com/rushairer/gosso/internal/oidc/service"
	"golang.org/x/crypto/bcrypt"
	"go.uber.org/zap"
)

//go:embed template/consent.html
var consentTemplateFS embed.FS

// OAuth2Controller OAuth2 协议控制器
type OAuth2Controller struct {
	clientSvc    oauth2Service.OAuth2ClientService
	authCodeSvc  *oauth2Service.AuthCodeService
	consentSvc   *oauth2Service.ConsentService
	tokenSvc     *tokenService.TokenService
	idTokenSvc   *oidcService.IDTokenService
	consentTmpl  *template.Template
	logger       *zap.Logger
}

// NewOAuth2Controller 创建 OAuth2 控制器实例
func NewOAuth2Controller(
	clientSvc oauth2Service.OAuth2ClientService,
	authCodeSvc *oauth2Service.AuthCodeService,
	consentSvc *oauth2Service.ConsentService,
	tokenSvc *tokenService.TokenService,
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

// RegisterRoutes 注册 OAuth2 路由
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

	accountID, _ := ctx.Get(middleware.ContextKeyAccountID)

	existingConsent, _ := c.consentSvc.GetConsent(ctx, accountID.(string), clientID)
	if existingConsent != nil {
		code, err := c.authCodeSvc.GenerateCode(ctx, clientID, accountID.(string), redirectURI, splitScope(scope), codeChallenge, codeChallengeMethod, nonce)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}
		redirectWithCode(ctx, redirectURI, code.Code, state)
		return
	}

	ctx.Header("Content-Type", "text/html; charset=utf-8")

	// 从请求中提取 access_token 传递给表单
	accessToken := ctx.GetHeader("Authorization")
	accessToken = strings.TrimPrefix(accessToken, "Bearer ")
	if accessToken == "" {
		accessToken = ctx.Query("access_token")
	}

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
		"AccessToken":         accessToken,
	})
}

// ConsentRequest 授权同意请求体
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

	// 表单中 approved 通过 button value 提交
	approved := ctx.PostForm("approved")
	req.Approved = approved == "true"

	accountID, _ := ctx.Get(middleware.ContextKeyAccountID)

	if !req.Approved {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "consent_denied"})
		return
	}

	scopes := splitScope(req.Scope)

	_ = c.consentSvc.SaveConsent(ctx, &oauth2Domain.Consent{
		AccountID: accountID.(string),
		ClientID:  req.ClientID,
		Scopes:    scopes,
	})

	code, err := c.authCodeSvc.GenerateCode(ctx, req.ClientID, accountID.(string), req.RedirectURI, scopes, req.CodeChallenge, req.CodeChallengeMethod, req.Nonce)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	redirectWithCode(ctx, req.RedirectURI, code.Code, req.State)
}

// TokenRequest 令牌交换请求体
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
		"expires_in":    900,
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
		"expires_in":    900,
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
		"expires_in":   900,
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

// IntrospectRequest Token Introspection 请求体
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

	// 客户端认证（Basic Auth 或 client_id/client_secret）
	clientID, clientSecret, hasBasicAuth := ctx.Request.BasicAuth()
	if !hasBasicAuth {
		clientID = ctx.PostForm("client_id")
		clientSecret = ctx.PostForm("client_secret")
	}

	if clientID != "" {
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
