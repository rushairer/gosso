package controller

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"
	"go.uber.org/zap"

	accountService "github.com/rushairer/gosso/internal/account/service"
	authMiddleware "github.com/rushairer/gosso/internal/auth/middleware"
	"github.com/rushairer/gosso/internal/controllerutil"
	oauth2Repo "github.com/rushairer/gosso/internal/oauth2/repository"
	oidcService "github.com/rushairer/gosso/internal/oidc/service"
	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	tokenService "github.com/rushairer/gosso/internal/token/service"
	"github.com/rushairer/gosso/middleware"
)

// userInfoErrorMap maps user info service errors to HTTP responses.
var userInfoErrorMap = []controllerutil.ErrorRule{
	{Sentinel: accountService.ErrAccountNotActive, Mapping: controllerutil.ErrorMapping{Status: http.StatusForbidden, Message: "account is not active"}},
}

// OIDCController OIDC protocol controller
type OIDCController struct {
	discoverySvc     *oidcService.DiscoveryService
	jwksSvc          *oidcService.JWKSService
	userInfoSvc      *oidcService.UserInfoService
	logoutSvc        *oidcService.LogoutService
	clientRepo       oauth2Repo.OAuth2ClientRepository
	tokenSvc         *tokenService.TokenService
	sessionValidator sessionDomain.SessionValidator
	issuer           string
	logger           *zap.Logger
}

// NewOIDCController creates a new instance of OIDCController
func NewOIDCController(
	discoverySvc *oidcService.DiscoveryService,
	jwksSvc *oidcService.JWKSService,
	userInfoSvc *oidcService.UserInfoService,
	logoutSvc *oidcService.LogoutService,
	clientRepo oauth2Repo.OAuth2ClientRepository,
	tokenSvc *tokenService.TokenService,
	sessionValidator sessionDomain.SessionValidator,
	issuer string,
	logger *zap.Logger,
) *OIDCController {
	return &OIDCController{
		discoverySvc:     discoverySvc,
		jwksSvc:          jwksSvc,
		userInfoSvc:      userInfoSvc,
		logoutSvc:        logoutSvc,
		clientRepo:       clientRepo,
		tokenSvc:         tokenSvc,
		sessionValidator: sessionValidator,
		issuer:           issuer,
		logger:           logger,
	}
}

// RegisterRoutes registers OIDC routes (UserInfo + Logout).
// .well-known routes are registered at the router layer for independent rate limiting.
// GET /logout is intentionally omitted to prevent CSRF via image tags or link prefetching.
// Clients must use POST or redirect with id_token_hint (handled in Logout).
func (c *OIDCController) RegisterRoutes(server *gin.RouterGroup, authMiddleware gin.HandlerFunc) {
	server.GET("/userinfo", authMiddleware, c.UserInfo)
	server.POST("/userinfo", authMiddleware, c.UserInfo)
	server.POST("/logout", c.Logout)
}

// Discovery GET /.well-known/openid-configuration
func (c *OIDCController) Discovery(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, c.discoverySvc.GetDiscoveryDocument())
}

// JWKS GET /.well-known/jwks.json
func (c *OIDCController) JWKS(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, c.jwksSvc.GetJWKS())
}

// UserInfo GET /oidc/userinfo
func (c *OIDCController) UserInfo(ctx *gin.Context) {
	jwtClaims, exists := ctx.Get(middleware.ContextKeyClaims)
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "no claims"))
		return
	}

	claims, ok := jwtClaims.(*tokenDomain.AccessTokenClaims)
	if !ok {
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "invalid claims type"))
		return
	}

	// Parse scope
	scopes := strings.Split(claims.Scope, " ")

	info, err := c.userInfoSvc.GetUserInfo(ctx, claims.AccountID, scopes)
	if err != nil {
		controllerutil.HandleServiceError(ctx, c.logger, err, userInfoErrorMap,
			http.StatusInternalServerError, "Failed to get user info")
		return
	}

	ctx.JSON(http.StatusOK, info)
}

// logoutRequest holds the parameters for OIDC RP-Initiated Logout.
type logoutRequest struct {
	IDTokenHint           string `form:"id_token_hint"`
	ClientID              string `form:"client_id"`
	PostLogoutRedirectURI string `form:"post_logout_redirect_uri"`
	State                 string `form:"state"`
}

// Logout handles POST /oidc/logout per OpenID Connect RP-Initiated Logout 1.0.
//
// CSRF note: CSRF middleware skips requests with a Bearer Authorization header,
// so if a Bearer token is present it MUST be validated here (not just forwarded).
// An invalid Bearer header is rejected immediately to prevent CSRF bypass via
// a forged Authorization header combined with a stolen id_token_hint.
func (c *OIDCController) Logout(ctx *gin.Context) {
	var req logoutRequest
	if err := ctx.ShouldBind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request"))
		return
	}

	// Security: CSRF middleware skips validation when a Bearer header is present.
	// If the Bearer header is invalid (or a forgery), reject immediately to prevent
	// CSRF bypass via a fake Authorization header combined with a stolen id_token_hint.
	bearerClaims := c.validateBearerToken(ctx)
	if ctx.IsAborted() {
		return
	}

	// Try logout paths in order: id_token_hint → Bearer token → anonymous
	var clientID string

	if req.IDTokenHint != "" {
		if cid, ok := c.tryLogoutByIDTokenHint(ctx, req, bearerClaims); ok {
			clientID = cid
		}
		if ctx.IsAborted() {
			return
		}
	}

	if clientID == "" && bearerClaims != nil {
		clientID = c.tryLogoutByBearerToken(ctx, bearerClaims)
		if ctx.IsAborted() {
			return
		}
	}

	// Post-logout redirect
	if req.PostLogoutRedirectURI != "" && clientID != "" {
		c.handlePostLogoutRedirect(ctx, req, clientID)
		return
	}

	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{"status": "logged_out"}))
}

// validateBearerToken validates the Bearer token from the Authorization header.
// Returns nil if no Bearer header is present. Aborts the request if the token is invalid.
func (c *OIDCController) validateBearerToken(ctx *gin.Context) *tokenDomain.AccessTokenClaims {
	if ctx.GetHeader("Authorization") == "" {
		return nil
	}
	claims, err := authMiddleware.ValidateBearerToken(ctx, c.tokenSvc, c.sessionValidator)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "invalid session"))
		ctx.Abort()
		return nil
	}
	return claims
}

// tryLogoutByIDTokenHint attempts logout using the id_token_hint parameter.
// Returns the resolved clientID and true on success, or ("", false) to fall through.
func (c *OIDCController) tryLogoutByIDTokenHint(ctx *gin.Context, req logoutRequest, bearerClaims *tokenDomain.AccessTokenClaims) (string, bool) {
	claims, err := c.logoutSvc.ValidateIDTokenHint(req.IDTokenHint)
	if err != nil {
		c.logger.Debug("id_token_hint validation failed, skipping", zap.Error(err))
		return "", false
	}

	// If client_id is provided, verify it matches the ID token audience
	if req.ClientID != "" {
		audMatch := false
		for _, aud := range claims.Audience {
			if aud == req.ClientID {
				audMatch = true
				break
			}
		}
		if !audMatch {
			ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "client_id does not match id_token_hint audience"))
			ctx.Abort()
			return "", true // handled (with error)
		}
	}

	accountID := claims.Subject

	// When both id_token_hint and Bearer token are present, verify identity match
	if bearerClaims != nil && bearerClaims.AccountID != accountID {
		ctx.JSON(http.StatusForbidden, gouno.NewErrorResponse(http.StatusForbidden,
			"id_token_hint subject does not match authenticated user"))
		ctx.Abort()
		return "", true // handled (with error)
	}

	if err := c.logoutSvc.LogoutByAccountID(ctx, accountID); err != nil {
		c.logger.Error("Logout by account ID failed", zap.String("account_id", accountID), zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "logout failed"))
		ctx.Abort()
		return "", true
	}

	// Blacklist the current access token if a Bearer header was also provided
	if bearerClaims != nil && bearerClaims.ExpiresAt != nil {
		if err := c.tokenSvc.RevokeAccessToken(ctx, bearerClaims.ID, bearerClaims.ExpiresAt.Time); err != nil {
			c.logger.Warn("Failed to blacklist access token during id_token_hint logout",
				zap.String("jti", bearerClaims.ID), zap.Error(err))
		}
	}

	clientID := ""
	if len(claims.Audience) > 0 {
		clientID = claims.Audience[0]
	}
	if req.ClientID != "" {
		clientID = req.ClientID
	}
	return clientID, true
}

// tryLogoutByBearerToken attempts logout using the validated Bearer token claims.
// Returns the resolved clientID, or "" if no logout was performed.
func (c *OIDCController) tryLogoutByBearerToken(ctx *gin.Context, claims *tokenDomain.AccessTokenClaims) string {
	if err := c.logoutSvc.LogoutBySessionID(ctx, claims.AccountID, claims.SessionID); err != nil {
		c.logger.Error("Logout by session ID failed", zap.String("session_id", claims.SessionID), zap.Error(err))
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "logout failed"))
		ctx.Abort()
		return ""
	}

	// Blacklist the current access token so it cannot be reused
	if claims.ExpiresAt != nil {
		if err := c.tokenSvc.RevokeAccessToken(ctx, claims.ID, claims.ExpiresAt.Time); err != nil {
			c.logger.Warn("Failed to blacklist access token during logout", zap.String("jti", claims.ID), zap.Error(err))
		}
	}

	return claims.ClientID
}

// handlePostLogoutRedirect validates and performs the post-logout redirect.
func (c *OIDCController) handlePostLogoutRedirect(ctx *gin.Context, req logoutRequest, clientID string) {
	client, err := c.clientRepo.FindByClientID(ctx, clientID)
	if err != nil {
		c.logger.Debug("Client lookup failed for post-logout redirect", zap.String("client_id", clientID), zap.Error(err))
		ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{"status": "logged_out"}))
		return
	}

	if !client.ValidatePostLogoutRedirectURI(req.PostLogoutRedirectURI) {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid post_logout_redirect_uri"))
		return
	}

	redirectURI := req.PostLogoutRedirectURI
	if req.State != "" {
		u, err := url.Parse(redirectURI)
		if err == nil {
			params := u.Query()
			params.Set("state", req.State)
			u.RawQuery = params.Encode()
			redirectURI = u.String()
		}
	}
	ctx.Redirect(http.StatusFound, redirectURI)
}
