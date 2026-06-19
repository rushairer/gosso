package gouno

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/config"
	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/middleware"
	"github.com/rushairer/gosso/router"
)

// setupEngine configures the Gin engine: middleware + routes
func setupEngine(ctx context.Context, cfg config.GoUnoConfig, logger *zap.Logger, m *appModules, db *sql.DB, redis *cache.RedisClient) (*gin.Engine, error) {
	engine := gin.New()
	if err := engine.SetTrustedProxies(cfg.WebServerConfig.TrustedProxies); err != nil {
		return nil, fmt.Errorf("invalid trusted proxies configuration: %w", err)
	}

	corsConfig, err := buildCORSConfig(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("invalid CORS configuration: %w", err)
	}

	engine.Use(
		middleware.RecoveryMiddleware(logger),
		cors.New(corsConfig),
		middleware.RequestIDMiddleware(),
		middleware.ZapLoggerMiddleware(logger),
		middleware.SecurityHeadersMiddleware(!cfg.WebServerConfig.Debug),
		middleware.MaxBodySizeMiddleware(cfg.WebServerConfig.MaxBodySize),
		middleware.TimeoutMiddleware(cfg.WebServerConfig.RequestTimeout),
		middleware.CSRFMiddleware(!cfg.WebServerConfig.Debug, logger, cfg.AuthConfig.CSRFCookieMaxAge,
			"/api/passkey/login/begin",
			"/api/passkey/login/complete",
			"/api/passkey/mfa/begin",
			"/api/passkey/mfa/complete",
			"/oauth2/token",
			"/oauth2/introspect",
			"/oauth2/device/code",
			"/.well-known",
			"/swagger",
		),
	)

	router.RegisterWebRouter(router.RouterDeps{
		Server:           engine,
		DB:               db,
		AuthCtrl:         m.authCtrl,
		OAuth2Ctrl:       m.oauth2Ctrl,
		ClientCtrl:       m.clientCtrl,
		OIDCCtrl:         m.oidcCtrl,
		AdminCtrl:        m.adminCtrl,
		TokenSvc:         m.tokenSvc,
		PasskeyCtrl:      m.passkeyCtrl,
		Redis:            redis,
		RateLimits:       cfg.WebServerConfig.RateLimits,
		Debug:            cfg.WebServerConfig.Debug,
		SessionValidator: m.sessionSvc,
		Logger:           logger,
	})

	return engine, nil
}

// buildCORSConfig builds CORS configuration from config.
// Returns an error in production mode when allowed_origins is empty.
func buildCORSConfig(cfg config.GoUnoConfig, logger *zap.Logger) (cors.Config, error) {
	corsConfig := cors.Config{
		AllowAllOrigins:  false,
		AllowCredentials: cfg.CORSConfig.AllowCredentials,
		MaxAge:           time.Duration(cfg.CORSConfig.MaxAge) * time.Second,
	}
	if len(cfg.CORSConfig.AllowedOrigins) > 0 {
		corsConfig.AllowOrigins = cfg.CORSConfig.AllowedOrigins
	} else if !cfg.WebServerConfig.Debug {
		return cors.Config{}, fmt.Errorf("cors: allowed_origins is required in production mode")
	} else {
		logger.Warn("CORS allowed_origins not configured, falling back to localhost — do not use this in production")
		corsConfig.AllowOrigins = []string{fmt.Sprintf("http://localhost:%s", cfg.WebServerConfig.Port)}
	}
	if len(cfg.CORSConfig.AllowedMethods) > 0 {
		corsConfig.AllowMethods = cfg.CORSConfig.AllowedMethods
	} else {
		corsConfig.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	}
	if len(cfg.CORSConfig.AllowedHeaders) > 0 {
		corsConfig.AllowHeaders = cfg.CORSConfig.AllowedHeaders
	} else {
		corsConfig.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization", "X-CSRF-Token"}
	}
	return corsConfig, nil
}
