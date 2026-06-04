package controller

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/auth/middleware"
	oauth2Repo "github.com/rushairer/gosso/internal/oauth2/repository"
	oidcService "github.com/rushairer/gosso/internal/oidc/service"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	tokenService "github.com/rushairer/gosso/internal/token/service"
)

// OIDCController OIDC protocol controller
type OIDCController struct {
	discoverySvc *oidcService.DiscoveryService
	jwksSvc      *oidcService.JWKSService
	userInfoSvc  *oidcService.UserInfoService
	logoutSvc    *oidcService.LogoutService
	clientRepo   oauth2Repo.OAuth2ClientRepository
	tokenSvc     *tokenService.TokenService
	issuer       string
	logger       *zap.Logger
}

// NewOIDCController creates a new instance of OIDCController
func NewOIDCController(
	discoverySvc *oidcService.DiscoveryService,
	jwksSvc *oidcService.JWKSService,
	userInfoSvc *oidcService.UserInfoService,
	logoutSvc *oidcService.LogoutService,
	clientRepo oauth2Repo.OAuth2ClientRepository,
	tokenSvc *tokenService.TokenService,
	issuer string,
	logger *zap.Logger,
) *OIDCController {
	return &OIDCController{
		discoverySvc: discoverySvc,
		jwksSvc:      jwksSvc,
		userInfoSvc:  userInfoSvc,
		logoutSvc:    logoutSvc,
		clientRepo:   clientRepo,
		tokenSvc:     tokenSvc,
		issuer:       issuer,
		logger:       logger,
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
		if err == oidcService.ErrAccountNotActive {
			ctx.JSON(http.StatusForbidden, gouno.NewErrorResponse(http.StatusForbidden, "account is not active"))
			return
		}
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to get user info"))
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
func (c *OIDCController) Logout(ctx *gin.Context) {
	var req logoutRequest
	if err := ctx.ShouldBind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid request"))
		return
	}

	var accountID string
	var clientID string
	loggedOut := false

	// 1. Try id_token_hint first
	if req.IDTokenHint != "" {
		claims, err := c.logoutSvc.ValidateIDTokenHint(req.IDTokenHint)
		if err != nil {
			c.logger.Debug("id_token_hint validation failed", zap.Error(err))
			ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid id_token_hint"))
			return
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
				return
			}
		}

		accountID = claims.Subject
		if len(claims.Audience) > 0 {
			clientID = claims.Audience[0]
		}
		if req.ClientID != "" {
			clientID = req.ClientID
		}

		if err := c.logoutSvc.LogoutByAccountID(ctx, accountID); err != nil {
			c.logger.Error("Logout by account ID failed", zap.String("account_id", accountID), zap.Error(err))
			ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "logout failed"))
			return
		}
		loggedOut = true
	}

	// 2. Fallback: try Bearer token
	if !loggedOut {
		authHeader := ctx.GetHeader("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			tokenClaims, err := c.tokenSvc.ValidateAccessTokenWithContext(ctx, tokenString)
			if err == nil && tokenClaims != nil {
				clientID = tokenClaims.ClientID
				if err := c.logoutSvc.LogoutBySessionID(ctx, tokenClaims.AccountID, tokenClaims.SessionID); err != nil {
					c.logger.Error("Logout by session ID failed", zap.String("session_id", tokenClaims.SessionID), zap.Error(err))
					ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "logout failed"))
					return
				}
				// Blacklist the current access token so it cannot be reused
				if tokenClaims.ExpiresAt != nil {
					if err := c.tokenSvc.RevokeAccessToken(ctx, tokenClaims.ID, tokenClaims.ExpiresAt.Time); err != nil {
						c.logger.Warn("Failed to blacklist access token during logout", zap.String("jti", tokenClaims.ID), zap.Error(err))
					}
				}
				loggedOut = true
			} else {
				c.logger.Debug("Bearer token validation failed during logout", zap.Error(err))
			}
		}
	}

	// 3. Post-logout redirect
	if req.PostLogoutRedirectURI != "" && clientID != "" {
		client, err := c.clientRepo.FindByClientID(ctx, clientID)
		if err != nil {
			c.logger.Debug("Client lookup failed for post-logout redirect", zap.String("client_id", clientID), zap.Error(err))
		} else if client.ValidatePostLogoutRedirectURI(req.PostLogoutRedirectURI) {
			redirectURI := req.PostLogoutRedirectURI
			if req.State != "" {
				params := url.Values{}
				params.Set("state", req.State)
				separator := "?"
				if u, err := url.Parse(redirectURI); err == nil && u.RawQuery != "" {
					separator = "&"
				}
				redirectURI = redirectURI + separator + params.Encode()
			}
			ctx.Redirect(http.StatusFound, redirectURI)
			return
		} else {
			ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid post_logout_redirect_uri"))
			return
		}
	}

	// 4. Default response
	if loggedOut {
		ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(gin.H{"status": "logged_out"}))
	} else {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "no session found, unable to logout"))
	}
}
