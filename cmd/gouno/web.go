package gouno

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/rushairer/gosso/config"
	"github.com/rushairer/gosso/internal/account"
	adminController "github.com/rushairer/gosso/internal/admin/controller"
	"github.com/rushairer/gosso/internal/auth"
	authController "github.com/rushairer/gosso/internal/auth/controller"
	authService "github.com/rushairer/gosso/internal/auth/service"
	"github.com/rushairer/gosso/internal/cache"
	auditService "github.com/rushairer/gosso/internal/audit/service"
	"github.com/rushairer/gosso/internal/oauth2"
	oauth2Controller "github.com/rushairer/gosso/internal/oauth2/controller"
	"github.com/rushairer/gosso/internal/oidc"
	oidcController "github.com/rushairer/gosso/internal/oidc/controller"
	tokenService "github.com/rushairer/gosso/internal/token/service"
	"github.com/rushairer/gosso/middleware"
	"github.com/rushairer/gosso/router"
	"github.com/rushairer/gosso/utility"
	gounoMiddleware "github.com/rushairer/gouno/middleware"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var webCmd = &cobra.Command{
	Use: "web",
	Run: startWebServer,
}

func init() {
	webCmd.Flags().StringP("config_path", "c", "./config", "config file path")
	webCmd.Flags().StringP("address", "a", "0.0.0.0", "address to listen on")
	webCmd.Flags().StringP("port", "p", "8080", "port to listen on")
	webCmd.Flags().BoolP("debug", "d", false, "debug mode")
	webCmd.Flags().StringP("env", "e", "production", "env: development, test, production")
}

func startWebServer(cmd *cobra.Command, args []string) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	configPath := cmd.Flag("config_path").Value.String()
	env := cmd.Flag("env").Value.String()

	configManager := config.NewConfigManager(cmd, configPath, env)
	globalConfig := configManager.Config()

	if globalConfig.WebServerConfig.Debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	loggerLevel := zap.NewAtomicLevelAt(zapcore.Level(globalConfig.LogConfig.Level))
	logger := utility.NewLogger(loggerLevel)

	logger.Sugar().Info("starting web server...")

	// init database
	defaultDriver := globalConfig.DatabaseConfig.GetDefaultDriver()
	if defaultDriver == nil {
		log.Fatalf("default database driver not found")
	}

	db, err := sql.Open(defaultDriver.Driver, defaultDriver.DSN)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(10 * time.Minute)

	if err := db.Ping(); err != nil {
		log.Fatalf("failed to ping database: %v", err)
	}
	logger.Sugar().Info("database connected")

	// init redis
	redis, err := cache.NewRedisClient(
		globalConfig.RedisConfig.DSN,
		globalConfig.RedisConfig.MaxActiveConns,
		time.Duration(globalConfig.RedisConfig.PoolTimeoutSeconds)*time.Second,
		logger,
	)
	if err != nil {
		log.Fatalf("failed to connect to redis: %v", err)
	}
	defer redis.Close()
	logger.Sugar().Info("redis connected")

	// init audit
	auditAuditor := auditService.NewAuditor(ctx, db)
	go func() {
		for err := range auditAuditor.ErrorChan() {
			logger.Error("Audit batch error", zap.Error(err))
		}
	}()

	// init modules
	accountSvc := account.InitializeAccountModule(db, auditAuditor)

	// init token services
	keySvc, err := tokenService.NewKeyService(
		globalConfig.AuthConfig.PrivateKeyPath,
		globalConfig.AuthConfig.KeyID,
		logger,
	)
	if err != nil {
		log.Fatalf("failed to initialize key service: %v", err)
	}

	blacklistSvc := tokenService.NewBlacklistService(redis, logger)
	tokenSvc := tokenService.NewTokenService(
		[]byte(globalConfig.AuthConfig.JWTSecret),
		keySvc,
		globalConfig.AuthConfig.Issuer,
		globalConfig.AuthConfig.AccessTokenExpiry,
		globalConfig.AuthConfig.RefreshTokenExpiry,
		redis,
		blacklistSvc,
		logger,
	)

	// build social login provider configs
	providers := make(map[string]*authService.OAuthProviderConfig)
	if globalConfig.OAuthProviders.Google.ClientID != "" {
		p := globalConfig.OAuthProviders.Google
		providers["google"] = &authService.OAuthProviderConfig{
			ClientID: p.ClientID, ClientSecret: p.ClientSecret, RedirectURI: p.RedirectURI, Scopes: p.Scopes,
			TokenURL: "https://oauth2.googleapis.com/token", UserInfoURL: "https://www.googleapis.com/oauth2/v2/userinfo",
		}
	}
	if globalConfig.OAuthProviders.GitHub.ClientID != "" {
		p := globalConfig.OAuthProviders.GitHub
		providers["github"] = &authService.OAuthProviderConfig{
			ClientID: p.ClientID, ClientSecret: p.ClientSecret, RedirectURI: p.RedirectURI, Scopes: p.Scopes,
			TokenURL: "https://github.com/login/oauth/access_token", UserInfoURL: "https://api.github.com/user",
		}
	}
	if globalConfig.OAuthProviders.WeChat.ClientID != "" {
		p := globalConfig.OAuthProviders.WeChat
		providers["wechat"] = &authService.OAuthProviderConfig{
			ClientID: p.ClientID, ClientSecret: p.ClientSecret, RedirectURI: p.RedirectURI, Scopes: p.Scopes,
			TokenURL: "https://api.weixin.qq.com/sns/oauth2/access_token", UserInfoURL: "https://api.weixin.qq.com/sns/userinfo",
		}
	}

	// init auth module (includes social login + verification + password reset)
	authSvc, socialSvc, verificationSvc, passwordResetSvc, credentialRepo, passkeySvc := auth.InitializeAuthModule(db, redis, logger, globalConfig.AuthConfig, globalConfig.SMTPConfig, accountSvc, providers, keySvc, globalConfig.AuthConfig.PasswordResetBaseURL, auditAuditor)

	// init oauth2 module
	oauth2ClientSvc, authCodeSvc, consentSvc := oauth2.InitializeOAuth2Module(db, redis, logger, globalConfig.AuthConfig)

	// init oidc module
	idTokenSvc, discoverySvc, jwksSvc, userInfoSvc := oidc.InitializeOIDCModule(db, tokenSvc, accountSvc, globalConfig.AuthConfig, logger)

	// init controllers
	authCtrl := authController.NewAuthController(authSvc, tokenSvc, socialSvc, verificationSvc, passwordResetSvc, credentialRepo, logger)
	oauth2Ctrl := oauth2Controller.NewOAuth2Controller(oauth2ClientSvc, authCodeSvc, consentSvc, tokenSvc, idTokenSvc, logger)
	clientCtrl := oauth2Controller.NewClientController(oauth2ClientSvc, logger)
	oidcCtrl := oidcController.NewOIDCController(discoverySvc, jwksSvc, userInfoSvc, logger)
	adminCtrl := adminController.NewAdminController(accountSvc, logger)

	var passkeyCtrl *authController.PasskeyController
	if passkeySvc != nil {
		passkeyCtrl = authController.NewPasskeyController(passkeySvc, authSvc, accountSvc, logger)
	}

	engine := gin.New()

	// CORS 配置
	corsConfig := cors.Config{
		AllowAllOrigins:  len(globalConfig.CORSConfig.AllowedOrigins) == 0,
		AllowCredentials: globalConfig.CORSConfig.AllowCredentials,
		MaxAge:           time.Duration(globalConfig.CORSConfig.MaxAge) * time.Second,
	}
	if len(globalConfig.CORSConfig.AllowedOrigins) > 0 {
		corsConfig.AllowOrigins = globalConfig.CORSConfig.AllowedOrigins
	}
	if len(globalConfig.CORSConfig.AllowedMethods) > 0 {
		corsConfig.AllowMethods = globalConfig.CORSConfig.AllowedMethods
	} else {
		corsConfig.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	}
	if len(globalConfig.CORSConfig.AllowedHeaders) > 0 {
		corsConfig.AllowHeaders = globalConfig.CORSConfig.AllowedHeaders
	} else {
		corsConfig.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization"}
	}

	engine.Use(
		cors.New(corsConfig),
		gin.Logger(),
		middleware.RecoveryMiddleware(),
		middleware.TimeoutMiddleware(globalConfig.WebServerConfig.RequestTimeout),
		gounoMiddleware.RateLimitMiddleware(ctx, globalConfig.WebServerConfig.RateLimitPerMinute, time.Minute),
		middleware.CSRFMiddleware(!globalConfig.WebServerConfig.Debug,
			"/api/auth/passkey/login",
			"/api/auth/social",
			"/oauth2",
			"/.well-known",
			"/swagger",
		),
	)
	router.RegisterWebRouter(engine, authCtrl, oauth2Ctrl, clientCtrl, oidcCtrl, adminCtrl, tokenSvc, passkeyCtrl, redis, globalConfig.WebServerConfig.RateLimits)

	httpServer := &http.Server{
		Addr:              fmt.Sprintf("%s:%s", globalConfig.WebServerConfig.Address, globalConfig.WebServerConfig.Port),
		IdleTimeout:       globalConfig.WebServerConfig.IdleTimeout,
		WriteTimeout:      globalConfig.WebServerConfig.WriteTimeout,
		ReadTimeout:       globalConfig.WebServerConfig.ReadTimeout,
		ReadHeaderTimeout: globalConfig.WebServerConfig.ReadHeaderTimeout,
		Handler:           engine,
	}

	logger.Sugar().Infof("web server listening on %s", httpServer.Addr)
	logger.Sugar().Info("press Ctrl+C to exit")

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	<-ctx.Done()

	stop()
	logger.Sugar().Info("shutting down gracefully, press Ctrl+C again to force")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Fatalf("server forced to shutdown: %v", err)
	}

	logger.Sugar().Info("server exiting")
}
