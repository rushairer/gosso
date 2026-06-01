package controller

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gosso/internal/auth/middleware"
	oidcService "github.com/rushairer/gosso/internal/oidc/service"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	"github.com/rushairer/gouno"
	"go.uber.org/zap"
)

// OIDCController OIDC 协议控制器
type OIDCController struct {
	discoverySvc *oidcService.DiscoveryService
	jwksSvc      *oidcService.JWKSService
	userInfoSvc  *oidcService.UserInfoService
	logger       *zap.Logger
}

// NewOIDCController 创建 OIDC 控制器实例
func NewOIDCController(
	discoverySvc *oidcService.DiscoveryService,
	jwksSvc *oidcService.JWKSService,
	userInfoSvc *oidcService.UserInfoService,
	logger *zap.Logger,
) *OIDCController {
	return &OIDCController{
		discoverySvc: discoverySvc,
		jwksSvc:      jwksSvc,
		userInfoSvc:  userInfoSvc,
		logger:       logger,
	}
}

// RegisterRoutes 注册 OIDC 路由
func (c *OIDCController) RegisterRoutes(server *gin.Engine, authMiddleware gin.HandlerFunc) {
	server.GET("/.well-known/openid-configuration", c.Discovery)
	server.GET("/.well-known/jwks.json", c.JWKS)
	server.GET("/oidc/userinfo", authMiddleware, c.UserInfo)
	server.POST("/oidc/userinfo", authMiddleware, c.UserInfo)
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

	// 解析 scope
	scopes := strings.Split(claims.Scope, " ")

	info, err := c.userInfoSvc.GetUserInfo(ctx, claims.AccountID, scopes)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "failed to get user info"))
		return
	}

	ctx.JSON(http.StatusOK, info)
}
