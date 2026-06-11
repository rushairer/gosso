package controller

import (
	"mime"
	"net/http"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/controllerutil"
	oauth2Domain "github.com/rushairer/gosso/internal/oauth2/domain"
	oauth2Service "github.com/rushairer/gosso/internal/oauth2/service"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
)

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
	// RFC 6749 §4.1.3 / §4.3.2: token endpoint MUST accept application/x-www-form-urlencoded.
	// Reject JSON content type to prevent WAF bypass attacks.
	if contentType := ctx.GetHeader("Content-Type"); contentType != "" {
		mediaType, _, _ := mime.ParseMediaType(contentType)
		if mediaType != "application/x-www-form-urlencoded" {
			ctx.JSON(http.StatusUnsupportedMediaType, gin.H{
				"error":             "invalid_request",
				"error_description": "Content-Type must be application/x-www-form-urlencoded",
			})
			return
		}
	}

	var req TokenRequest
	if err := ctx.ShouldBind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	// RFC 6749 §2.3.1: When Basic Auth is present, it takes precedence over body parameters.
	if clientID, clientSecret, ok := ctx.Request.BasicAuth(); ok {
		req.ClientID = clientID
		req.ClientSecret = clientSecret
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
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}

	if !client.HasGrantType("authorization_code") {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "unauthorized_client", "error_description": "client is not authorized for authorization_code grant"})
		return
	}

	if err := c.clientAuth.AuthenticateClient(client, req.ClientSecret); err != nil {
		controllerutil.HandleClientAuthError(ctx, err,
			oauth2Service.ErrClientSecretRequired,
			"client_secret required", "invalid client_secret")
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
			idToken, idErr = c.idTokenSvc.GenerateIDToken(ctx, authCode.AccountID, authCode.ClientID, authCode.Scopes, authCode.Nonce, authCode.AuthTime, accessToken)
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

	setNoCacheHeaders(ctx)
	ctx.JSON(http.StatusOK, response)
}

func (c *OAuth2Controller) handleRefreshTokenGrant(ctx *gin.Context, req *TokenRequest) {
	// Non-destructive read first to validate client before consuming the token
	oldRefreshToken, err := c.tokenSvc.ValidateRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "invalid refresh token"})
		return
	}

	// Verify IP binding — reject refresh from a different IP to prevent token theft.
	// If the original token has no IP recorded (legacy), skip validation.
	if oldRefreshToken.IP != "" && oldRefreshToken.IP != ctx.ClientIP() {
		c.logger.Warn("Refresh token IP mismatch",
			zap.String("original_ip", oldRefreshToken.IP),
			zap.String("current_ip", ctx.ClientIP()),
			zap.String("account_id", oldRefreshToken.AccountID))
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "refresh token IP mismatch"})
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
		controllerutil.HandleClientAuthError(ctx, err,
			oauth2Service.ErrClientSecretRequired,
			"client_secret required for confidential clients", "invalid client_secret")
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

	accessTokenScope := newRefreshToken.Scope
	if req.Scope != "" {
		accessTokenScope = req.Scope
	}
	accessToken, err := c.tokenSvc.GenerateAccessToken(&tokenDomain.AccessTokenClaims{
		AccountID: newRefreshToken.AccountID,
		Scope:     accessTokenScope,
		ClientID:  newRefreshToken.ClientID,
		SessionID: newRefreshToken.SessionID,
	})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	setNoCacheHeaders(ctx)
	ctx.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": newRefreshToken.Token,
		"token_type":    "Bearer",
		"expires_in":    int(c.tokenSvc.AccessExpiry().Seconds()),
		"scope":         accessTokenScope,
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

	setNoCacheHeaders(ctx)
	ctx.JSON(http.StatusOK, gin.H{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(c.tokenSvc.AccessExpiry().Seconds()),
		"scope":        strings.Join(scopes, " "),
	})
}
