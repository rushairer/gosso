package router

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/config"
	"github.com/rushairer/gosso/docs"
	adminController "github.com/rushairer/gosso/internal/admin/controller"
	authController "github.com/rushairer/gosso/internal/auth/controller"
	authMiddleware "github.com/rushairer/gosso/internal/auth/middleware"
	"github.com/rushairer/gosso/internal/cache"
	oauth2Controller "github.com/rushairer/gosso/internal/oauth2/controller"
	oidcController "github.com/rushairer/gosso/internal/oidc/controller"
	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
	tokenService "github.com/rushairer/gosso/internal/token/service"
	"github.com/rushairer/gosso/middleware"
)

// RouterDeps holds all dependencies for route registration.
type RouterDeps struct {
	Server           *gin.Engine
	DB               *sql.DB
	AuthCtrl         *authController.AuthController
	OAuth2Ctrl       *oauth2Controller.OAuth2Controller
	ClientCtrl       *oauth2Controller.ClientController
	OIDCCtrl         *oidcController.OIDCController
	AdminCtrl        *adminController.AdminController
	TokenSvc         *tokenService.TokenService
	PasskeyCtrl      *authController.PasskeyController
	Redis            *cache.RedisClient
	RateLimits       config.RateLimitsConfig
	Debug            bool
	SessionValidator sessionDomain.SessionValidator
	Logger           *zap.Logger
	StartTime        time.Time
}

// RegisterWebRouter registers all routes
func RegisterWebRouter(deps RouterDeps) {
	// Health check (no auth, no rate limiting)
	registerHealthRoutes(deps.Server, deps.DB, deps.Redis, deps.StartTime)

	// Test routes (debug only)
	if deps.Debug {
		registerWebTestRouter(deps.Server)
	}
	registerWebIndexRouter(deps.Server)

	// Swagger UI (debug only)
	if deps.Debug {
		registerSwaggerRouter(deps.Server)
	}

	// JWT auth middleware
	jwtAuth := authMiddleware.JWTAuthMiddleware(deps.TokenSvc, deps.SessionValidator)

	// Per-endpoint rate limiting middleware
	// Security-sensitive endpoints fail-closed (reject if Redis is unavailable)
	loginLimit := middleware.RedisRateLimitMiddleware(deps.Redis, "login", middleware.IPKeyFunc, deps.RateLimits.Login, time.Minute, false, deps.Logger)
	mfaLimit := middleware.RedisRateLimitMiddleware(deps.Redis, "mfa", middleware.IPKeyFunc, deps.RateLimits.Token, time.Minute, false, deps.Logger)
	passkeyLimit := middleware.RedisRateLimitMiddleware(deps.Redis, "passkey", middleware.IPKeyFunc, deps.RateLimits.Passkey, time.Minute, false, deps.Logger)
	refreshLimit := middleware.RedisRateLimitMiddleware(deps.Redis, "refresh", middleware.IPKeyFunc, deps.RateLimits.Token, time.Minute, false, deps.Logger)
	// Security-sensitive endpoints fail-closed (reject if Redis is unavailable)
	passwordLimit := middleware.RedisRateLimitMiddleware(deps.Redis, "password", middleware.IPKeyFunc, deps.RateLimits.Password, time.Minute, false, deps.Logger)
	verifyLimit := middleware.RedisRateLimitMiddleware(deps.Redis, "verify", middleware.IPKeyFunc, deps.RateLimits.Verify, time.Minute, false, deps.Logger)
	// Non-security endpoints fail-open (allow if Redis is unavailable)
	socialLimit := middleware.RedisRateLimitMiddleware(deps.Redis, "social", middleware.IPKeyFunc, deps.RateLimits.API, time.Minute, true, deps.Logger)

	// /api/* routes
	api := deps.Server.Group("/api")
	{
		// Auth routes (audit middleware injects IP/UserAgent)
		api.Use(authMiddleware.AuditMetadataMiddleware())
		deps.AuthCtrl.RegisterRoutes(api, authController.AuthRouteConfig{
			JWTAuth:       jwtAuth,
			LoginLimit:    loginLimit,
			MFALimit:      mfaLimit,
			PasswordLimit: passwordLimit,
			RefreshLimit:  refreshLimit,
			VerifyLimit:   verifyLimit,
			SocialLimit:   socialLimit,
		})

		// Client management routes (require JWT authentication + fail-closed rate limiting)
		clientLimit := middleware.RedisRateLimitMiddleware(deps.Redis, "client", middleware.IPKeyFunc, deps.RateLimits.API, time.Minute, false, deps.Logger)
		clientGroup := api.Group("")
		clientGroup.Use(clientLimit)
		deps.ClientCtrl.RegisterRoutes(clientGroup, jwtAuth)

		// Admin routes (require JWT authentication + admin role + rate limiting)
		admin := api.Group("/admin")
		adminLimit := middleware.RedisRateLimitMiddleware(deps.Redis, "admin", middleware.IPKeyFunc, deps.RateLimits.API, time.Minute, false, deps.Logger)
		admin.Use(adminLimit, jwtAuth, authMiddleware.AdminRequiredMiddleware())
		deps.AdminCtrl.RegisterRoutes(admin)

		// Passkey routes (MFA endpoints have their own rate limiting inside RegisterRoutes)
		if deps.PasskeyCtrl != nil {
			passkeyGroup := api.Group("")
			deps.PasskeyCtrl.RegisterRoutes(passkeyGroup, jwtAuth, passkeyLimit)
		}
	}

	// OAuth2 protocol routes (with rate limiting for token endpoint)
	tokenLimit := middleware.RedisRateLimitMiddleware(deps.Redis, "oauth2-token", middleware.IPKeyFunc, deps.RateLimits.Token, time.Minute, false, deps.Logger)
	introspectLimit := middleware.RedisRateLimitMiddleware(deps.Redis, "introspect", middleware.IPKeyFunc, deps.RateLimits.Introspect, time.Minute, false, deps.Logger)
	deviceCodeLimit := middleware.RedisRateLimitMiddleware(deps.Redis, "device-code", middleware.IPKeyFunc, deps.RateLimits.DeviceCode, time.Minute, false, deps.Logger)
	deviceUserLimit := middleware.RedisRateLimitMiddleware(deps.Redis, "device-user", middleware.IPKeyFunc, deps.RateLimits.DeviceCode, time.Minute, false, deps.Logger)
	oauth2 := deps.Server.Group("/oauth2")
	oauth2.Use(authMiddleware.AuditMetadataMiddleware())
	deps.OAuth2Ctrl.RegisterRoutes(oauth2, jwtAuth, tokenLimit, introspectLimit, deviceCodeLimit, deviceUserLimit)

	// OIDC routes
	// .well-known endpoints (Discovery + JWKS) — rate-limited, fail-closed
	wellKnownLimit := middleware.RedisRateLimitMiddleware(deps.Redis, "well-known", middleware.IPKeyFunc, deps.RateLimits.API, time.Minute, false, deps.Logger)
	wellKnown := deps.Server.Group("/.well-known")
	wellKnown.Use(wellKnownLimit)
	wellKnown.GET("/openid-configuration", deps.OIDCCtrl.Discovery)
	wellKnown.GET("/jwks.json", deps.OIDCCtrl.JWKS)

	// /oidc/* endpoints (UserInfo + Logout) — rate-limited, fail-closed
	oidcLimit := middleware.RedisRateLimitMiddleware(deps.Redis, "oidc", middleware.IPKeyFunc, deps.RateLimits.API, time.Minute, false, deps.Logger)
	oidc := deps.Server.Group("/oidc")
	oidc.Use(oidcLimit, authMiddleware.AuditMetadataMiddleware())
	deps.OIDCCtrl.RegisterRoutes(oidc, jwtAuth)
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

func registerHealthRoutes(server *gin.Engine, db *sql.DB, redis *cache.RedisClient, startTime time.Time) {
	server.GET("/health", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"uptime": time.Since(startTime).String(),
		})
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

		statusStr := "ok"
		if !ready {
			statusStr = "unavailable"
		}

		status := http.StatusOK
		if !ready {
			status = http.StatusServiceUnavailable
		}

		ctx.JSON(status, gin.H{
			"status": statusStr,
			"ready":  ready,
			"checks": checks,
		})
	})
}
