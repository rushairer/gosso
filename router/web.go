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

// RegisterWebRouter registers all routes
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
	debug bool,
	sessionValidator authMiddleware.SessionValidator,
) {
	// Health check (no auth, no rate limiting)
	registerHealthRoutes(server, db, redis)

	// Test routes (debug only)
	if debug {
		registerWebTestRouter(server)
	}
	registerWebIndexRouter(server)

	// Swagger UI (debug only)
	if debug {
		registerSwaggerRouter(server)
	}

	// JWT auth middleware
	jwtAuth := authMiddleware.JWTAuthMiddleware(tokenSvc, sessionValidator)

	// Per-endpoint rate limiting middleware
	// Security-sensitive endpoints fail-closed (reject if Redis is unavailable)
	loginLimit := middleware.RedisRateLimitMiddleware(redis, middleware.IPKeyFunc, rateLimits.Login, time.Minute, false)
	mfaLimit := middleware.RedisRateLimitMiddleware(redis, middleware.IPKeyFunc, rateLimits.Token, time.Minute, false)
	passkeyLimit := middleware.RedisRateLimitMiddleware(redis, middleware.IPKeyFunc, rateLimits.Passkey, time.Minute, false)
	refreshLimit := middleware.RedisRateLimitMiddleware(redis, middleware.IPKeyFunc, rateLimits.Token, time.Minute, false)
	// Non-security endpoints fail-open (allow if Redis is unavailable)
	passwordLimit := middleware.RedisRateLimitMiddleware(redis, middleware.IPKeyFunc, rateLimits.API, time.Minute, true)
	verifyLimit := middleware.RedisRateLimitMiddleware(redis, middleware.IPKeyFunc, rateLimits.API, time.Minute, true)
	socialLimit := middleware.RedisRateLimitMiddleware(redis, middleware.IPKeyFunc, rateLimits.API, time.Minute, true)

	// /api/* routes
	api := server.Group("/api")
	{
		// Auth routes (audit middleware injects IP/UserAgent)
		api.Use(authMiddleware.AuditMetadataMiddleware())
		authCtrl.RegisterRoutes(api, jwtAuth, loginLimit, mfaLimit, passwordLimit, refreshLimit, verifyLimit, socialLimit)

		// Client management routes (require JWT authentication + rate limiting)
		clientLimit := middleware.RedisRateLimitMiddleware(redis, middleware.IPKeyFunc, rateLimits.API, time.Minute, true)
		clientGroup := api.Group("")
		clientGroup.Use(clientLimit)
		clientCtrl.RegisterRoutes(clientGroup, jwtAuth)

		// Admin routes (require JWT authentication + admin role + rate limiting)
		admin := api.Group("/admin")
		adminLimit := middleware.RedisRateLimitMiddleware(redis, middleware.IPKeyFunc, rateLimits.API, time.Minute, false)
		admin.Use(adminLimit, jwtAuth, authMiddleware.AdminRequiredMiddleware())
		adminCtrl.RegisterRoutes(admin)

		// Passkey routes (MFA endpoints have their own rate limiting inside RegisterRoutes)
		if passkeyCtrl != nil {
			passkeyGroup := api.Group("")
			passkeyCtrl.RegisterRoutes(passkeyGroup, jwtAuth, passkeyLimit)
		}
	}

	// OAuth2 protocol routes (with rate limiting for token endpoint)
	tokenLimit := middleware.RedisRateLimitMiddleware(redis, middleware.IPKeyFunc, rateLimits.Token, time.Minute, false)
	introspectLimit := middleware.RedisRateLimitMiddleware(redis, middleware.IPKeyFunc, rateLimits.Introspect, time.Minute, false)
	deviceCodeLimit := middleware.RedisRateLimitMiddleware(redis, middleware.IPKeyFunc, rateLimits.DeviceCode, time.Minute, false)
	oauth2 := server.Group("/oauth2")
	oauth2.Use(tokenLimit)
	oauth2Ctrl.RegisterRoutes(oauth2, jwtAuth, introspectLimit, deviceCodeLimit)

	// OIDC routes
	// .well-known endpoints (Discovery + JWKS) — rate-limited, fail-closed
	wellKnownLimit := middleware.RedisRateLimitMiddleware(redis, middleware.IPKeyFunc, rateLimits.API, time.Minute, false)
	wellKnown := server.Group("/.well-known")
	wellKnown.Use(wellKnownLimit)
	wellKnown.GET("/openid-configuration", oidcCtrl.Discovery)
	wellKnown.GET("/jwks.json", oidcCtrl.JWKS)

	// /oidc/* endpoints (UserInfo + Logout) — rate-limited, fail-closed
	oidcLimit := middleware.RedisRateLimitMiddleware(redis, middleware.IPKeyFunc, rateLimits.API, time.Minute, false)
	oidc := server.Group("/oidc")
	oidc.Use(oidcLimit)
	oidcCtrl.RegisterRoutes(oidc, jwtAuth)
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
