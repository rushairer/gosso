package router

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"

	"github.com/rushairer/gosso/config"
	"github.com/rushairer/gosso/docs"
	adminController "github.com/rushairer/gosso/internal/admin/controller"
	authController "github.com/rushairer/gosso/internal/auth/controller"
	authMiddleware "github.com/rushairer/gosso/internal/auth/middleware"
	"github.com/rushairer/gosso/internal/cache"
	oauth2Controller "github.com/rushairer/gosso/internal/oauth2/controller"
	oidcController "github.com/rushairer/gosso/internal/oidc/controller"
	tokenService "github.com/rushairer/gosso/internal/token/service"
	"github.com/rushairer/gosso/middleware"
)

// RegisterWebRouter 注册所有路由
func RegisterWebRouter(
	server *gin.Engine,
	db *sql.DB,
	authCtrl *authController.AuthController,
	oauth2Ctrl *oauth2Controller.OAuth2Controller,
	clientCtrl *oauth2Controller.ClientController,
	oidcCtrl *oidcController.OIDCController,
	adminCtrl *adminController.AdminController,
	tokenSvc *tokenService.TokenService,
	passkeyCtrl *authController.PasskeyController,
	redis *cache.RedisClient,
	rateLimits config.RateLimitsConfig,
) {
	// 健康检查（无认证，无限流）
	registerHealthRoutes(server, db, redis)

	// 测试路由
	registerWebTestRouter(server)
	registerWebIndexRouter(server)

	// Swagger UI
	registerSwaggerRouter(server)

	// JWT 认证中间件
	jwtAuth := authMiddleware.JWTAuthMiddleware(tokenSvc)

	// Per-endpoint 限流中间件
	loginLimit := middleware.RedisRateLimitMiddleware(redis, middleware.IPKeyFunc, rateLimits.Login, time.Minute)
	mfaLimit := middleware.RedisRateLimitMiddleware(redis, middleware.IPKeyFunc, rateLimits.Token, time.Minute)
	passwordLimit := middleware.RedisRateLimitMiddleware(redis, middleware.IPKeyFunc, rateLimits.API, time.Minute)
	passkeyLimit := middleware.RedisRateLimitMiddleware(redis, middleware.IPKeyFunc, rateLimits.Passkey, time.Minute)

	// /api/* 路由
	api := server.Group("/api")
	{
		// 认证路由（审计中间件注入 IP/UserAgent）
		api.Use(authMiddleware.AuditMetadataMiddleware())
		authCtrl.RegisterRoutes(api, loginLimit, mfaLimit, passwordLimit)

		// 客户端管理路由（需要 JWT 认证）
		clientCtrl.RegisterRoutes(api, jwtAuth)

		// 管理员路由（需要 JWT 认证 + admin 角色 + 限流）
		admin := api.Group("/admin")
		adminLimit := middleware.RedisRateLimitMiddleware(redis, middleware.IPKeyFunc, rateLimits.API, time.Minute)
		admin.Use(adminLimit, jwtAuth, authMiddleware.AdminRequiredMiddleware())
		adminCtrl.RegisterRoutes(admin)

		// Passkey 路由（带限流）
		if passkeyCtrl != nil {
			passkeyGroup := api.Group("")
			passkeyGroup.Use(passkeyLimit)
			passkeyCtrl.RegisterRoutes(passkeyGroup, jwtAuth)
		}
	}

	// OAuth2 协议路由
	oauth2Ctrl.RegisterRoutes(server, jwtAuth)

	// OIDC 路由
	oidcCtrl.RegisterRoutes(server, jwtAuth)
}

func registerWebTestRouter(server *gin.Engine) {
	testGroup := server.Group("/test")
	{
		testGroup.GET(
			"/alive",
			func(ctx *gin.Context) {
				ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("pong"))
			},
		)
	}
}

func registerWebIndexRouter(server *gin.Engine) {
	server.GET("/", func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "Hello gouno!")
	})
}

func registerSwaggerRouter(server *gin.Engine) {
	swagger := server.Group("/swagger")
	{
		swagger.GET("", func(ctx *gin.Context) {
			ctx.Redirect(http.StatusMovedPermanently, "/swagger/index.html")
		})
		swagger.GET("/index.html", func(ctx *gin.Context) {
			ctx.Data(http.StatusOK, "text/html; charset=utf-8", docs.SwaggerUI)
		})
		swagger.GET("/openapi.yaml", func(ctx *gin.Context) {
			ctx.Data(http.StatusOK, "application/yaml", docs.OpenAPISpec)
		})
	}
}

func registerHealthRoutes(server *gin.Engine, db *sql.DB, redis *cache.RedisClient) {
	server.GET("/health", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	server.GET("/readiness", func(ctx *gin.Context) {
		checks := make(map[string]string)
		ready := true

		pingCtx, cancel := context.WithTimeout(ctx.Request.Context(), 2*time.Second)
		defer cancel()

		if err := db.PingContext(pingCtx); err != nil {
			checks["database"] = "unavailable"
			ready = false
		} else {
			checks["database"] = "ok"
		}

		if err := redis.Ping(pingCtx); err != nil {
			checks["redis"] = "unavailable"
			ready = false
		} else {
			checks["redis"] = "ok"
		}

		status := http.StatusOK
		if !ready {
			status = http.StatusServiceUnavailable
		}

		ctx.JSON(status, gin.H{
			"status": status,
			"ready":  ready,
			"checks": checks,
		})
	})
}
