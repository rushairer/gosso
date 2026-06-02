package gouno

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/rushairer/gosso/config"
	"github.com/rushairer/gosso/internal/account"
	adminController "github.com/rushairer/gosso/internal/admin/controller"
	auditService "github.com/rushairer/gosso/internal/audit/service"
	"github.com/rushairer/gosso/internal/auth"
	authController "github.com/rushairer/gosso/internal/auth/controller"
	authService "github.com/rushairer/gosso/internal/auth/service"
	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/oauth2"
	oauth2Controller "github.com/rushairer/gosso/internal/oauth2/controller"
	oauth2Repo "github.com/rushairer/gosso/internal/oauth2/repository"
	"github.com/rushairer/gosso/internal/oidc"
	oidcController "github.com/rushairer/gosso/internal/oidc/controller"
	tokenService "github.com/rushairer/gosso/internal/token/service"
	"github.com/rushairer/gosso/middleware"
	"github.com/rushairer/gosso/router"
	"github.com/rushairer/gosso/utility"
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

	if err := globalConfig.Validate(); err != nil {
		logger.Fatal("invalid configuration", zap.Error(err))
	}

	logger.Sugar().Info("starting web server...")

	db, err := initDatabase(globalConfig, logger)
	if err != nil {
		logger.Fatal("database init failed", zap.Error(err))
	}
	defer func() { _ = db.Close() }()

	redis, err := initRedis(globalConfig, logger)
	if err != nil {
		logger.Fatal("redis init failed", zap.Error(err))
	}
	defer func() { _ = redis.Close() }()

	auditAuditor := auditService.NewAuditor(ctx, db)
	defer auditAuditor.Close()
	go listenAuditErrors(ctx, auditAuditor, logger)

	modules := initModules(ctx, db, redis, logger, globalConfig, auditAuditor)

	engine := setupEngine(ctx, globalConfig, logger, modules, db, redis)

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
			logger.Fatal("listen failed", zap.Error(err))
		}
	}()

	<-ctx.Done()

	stop()
	logger.Sugar().Info("shutting down gracefully, press Ctrl+C again to force")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Fatal("server forced to shutdown", zap.Error(err))
	}

	logger.Sugar().Info("server exiting")
}

// initDatabase initializes the database connection
func initDatabase(cfg config.GoUnoConfig, logger *zap.Logger) (*sql.DB, error) {
	defaultDriver := cfg.DatabaseConfig.GetDefaultDriver()
	if defaultDriver == nil {
		return nil, fmt.Errorf("default database driver not found")
	}

	db, err := sql.Open(defaultDriver.Driver, defaultDriver.DSN)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(10 * time.Minute)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	logger.Sugar().Info("database connected")
	return db, nil
}

// initRedis initializes the Redis connection
func initRedis(cfg config.GoUnoConfig, logger *zap.Logger) (*cache.RedisClient, error) {
	redis, err := cache.NewRedisClient(
		cfg.RedisConfig.DSN,
		cfg.RedisConfig.MaxActiveConns,
		time.Duration(cfg.RedisConfig.PoolTimeoutSeconds)*time.Second,
		logger,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	logger.Sugar().Info("redis connected")
	return redis, nil
}

// listenAuditErrors listens for audit errors and logs them
func listenAuditErrors(ctx context.Context, auditor *auditService.Auditor, logger *zap.Logger) {
	for {
		select {
		case err, ok := <-auditor.ErrorChan():
			if !ok {
				return
			}
			logger.Error("Audit batch error", zap.Error(err))
		case <-ctx.Done():
			return
		}
	}
}

// appModules aggregates all initialized modules and controllers
type appModules struct {
	authCtrl    *authController.AuthController
	oauth2Ctrl  *oauth2Controller.OAuth2Controller
	clientCtrl  *oauth2Controller.ClientController
	oidcCtrl    *oidcController.OIDCController
	adminCtrl   *adminController.AdminController
	passkeyCtrl *authController.PasskeyController
	tokenSvc    *tokenService.TokenService
}

// initModules initializes all business modules and controllers
func initModules(ctx context.Context, db *sql.DB, redis *cache.RedisClient, logger *zap.Logger, cfg config.GoUnoConfig, auditor *auditService.Auditor) *appModules {
	accountSvc := account.InitializeAccountModule(db, auditor)

	keySvc, err := tokenService.NewKeyService(
		cfg.AuthConfig.PrivateKeyPath,
		cfg.AuthConfig.KeyID,
		logger,
	)
	if err != nil {
		logger.Fatal("failed to initialize key service", zap.Error(err))
	}

	blacklistSvc := tokenService.NewBlacklistService(redis, logger)
	tokenSvc := tokenService.NewTokenService(
		[]byte(cfg.AuthConfig.JWTSecret),
		keySvc,
		cfg.AuthConfig.Issuer,
		cfg.AuthConfig.AccessTokenExpiry,
		cfg.AuthConfig.RefreshTokenExpiry,
		redis,
		blacklistSvc,
		logger,
	)

	providers := buildOAuthProviders(cfg)

	authMod := auth.InitializeAuthModule(
		db, redis, logger, cfg.AuthConfig, cfg.SMTPConfig, accountSvc, providers, keySvc, cfg.AuthConfig.PasswordResetBaseURL, auditor, tokenSvc,
	)

	oauth2ClientSvc, authCodeSvc, consentSvc, deviceCodeSvc := oauth2.InitializeOAuth2Module(db, redis, logger, cfg.AuthConfig)
	idTokenSvc, discoverySvc, jwksSvc, userInfoSvc, logoutSvc := oidc.InitializeOIDCModule(db, tokenSvc, accountSvc, cfg.AuthConfig, authMod.SessionService, logger)

	clientRepo := oauth2Repo.NewOAuth2ClientRepository(db)
	authCtrl := authController.NewAuthController(authMod.AuthService, tokenSvc, authMod.SocialLoginService, authMod.VerificationService, authMod.PasswordResetService, authMod.CredentialRepo, logger)
	oauth2Ctrl := oauth2Controller.NewOAuth2Controller(oauth2ClientSvc, authCodeSvc, consentSvc, tokenSvc, idTokenSvc, deviceCodeSvc, cfg.AuthConfig.Issuer, logger)
	clientCtrl := oauth2Controller.NewClientController(oauth2ClientSvc, logger)
	oidcCtrl := oidcController.NewOIDCController(discoverySvc, jwksSvc, userInfoSvc, logoutSvc, clientRepo, tokenSvc, cfg.AuthConfig.Issuer, logger)
	adminCtrl := adminController.NewAdminController(accountSvc, logger)

	var passkeyCtrl *authController.PasskeyController
	if authMod.PasskeyService != nil {
		passkeyCtrl = authController.NewPasskeyController(authMod.PasskeyService, authMod.AuthService, tokenSvc, accountSvc, logger)
	}

	return &appModules{
		authCtrl:    authCtrl,
		oauth2Ctrl:  oauth2Ctrl,
		clientCtrl:  clientCtrl,
		oidcCtrl:    oidcCtrl,
		adminCtrl:   adminCtrl,
		passkeyCtrl: passkeyCtrl,
		tokenSvc:    tokenSvc,
	}
}

// buildOAuthProviders builds OAuth provider mappings from configuration
func buildOAuthProviders(cfg config.GoUnoConfig) map[string]*authService.OAuthProviderConfig {
	providers := make(map[string]*authService.OAuthProviderConfig)
	if cfg.OAuthProviders.Google.ClientID != "" {
		p := cfg.OAuthProviders.Google
		providers["google"] = &authService.OAuthProviderConfig{
			ClientID: p.ClientID, ClientSecret: p.ClientSecret, RedirectURI: p.RedirectURI, Scopes: p.Scopes,
			AuthURL:     defaultIfEmpty(p.AuthURL, "https://accounts.google.com/o/oauth2/v2/auth"),
			TokenURL:    defaultIfEmpty(p.TokenURL, "https://oauth2.googleapis.com/token"),
			UserInfoURL: defaultIfEmpty(p.UserInfoURL, "https://www.googleapis.com/oauth2/v2/userinfo"),
		}
	}
	if cfg.OAuthProviders.GitHub.ClientID != "" {
		p := cfg.OAuthProviders.GitHub
		providers["github"] = &authService.OAuthProviderConfig{
			ClientID: p.ClientID, ClientSecret: p.ClientSecret, RedirectURI: p.RedirectURI, Scopes: p.Scopes,
			AuthURL:     defaultIfEmpty(p.AuthURL, "https://github.com/login/oauth/authorize"),
			TokenURL:    defaultIfEmpty(p.TokenURL, "https://github.com/login/oauth/access_token"),
			UserInfoURL: defaultIfEmpty(p.UserInfoURL, "https://api.github.com/user"),
		}
	}
	if cfg.OAuthProviders.WeChat.ClientID != "" {
		p := cfg.OAuthProviders.WeChat
		providers["wechat"] = &authService.OAuthProviderConfig{
			ClientID: p.ClientID, ClientSecret: p.ClientSecret, RedirectURI: p.RedirectURI, Scopes: p.Scopes,
			AuthURL:     defaultIfEmpty(p.AuthURL, "https://open.weixin.qq.com/connect/qrconnect"),
			TokenURL:    defaultIfEmpty(p.TokenURL, "https://api.weixin.qq.com/sns/oauth2/access_token"),
			UserInfoURL: defaultIfEmpty(p.UserInfoURL, "https://api.weixin.qq.com/sns/userinfo"),
		}
	}
	return providers
}

func defaultIfEmpty(value, defaultValue string) string {
	if value == "" {
		return defaultValue
	}
	return value
}

// setupEngine configures the Gin engine: middleware + routes
func setupEngine(ctx context.Context, cfg config.GoUnoConfig, logger *zap.Logger, m *appModules, db *sql.DB, redis *cache.RedisClient) *gin.Engine {
	engine := gin.New()

	corsConfig := buildCORSConfig(cfg)

	engine.Use(
		cors.New(corsConfig),
		middleware.RequestIDMiddleware(),
		middleware.ZapLoggerMiddleware(logger),
		middleware.RecoveryMiddleware(),
		middleware.TimeoutMiddleware(cfg.WebServerConfig.RequestTimeout),
		middleware.CSRFMiddleware(!cfg.WebServerConfig.Debug,
			"/api/auth/passkey/login",
			"/api/auth/social",
			"/oauth2",
			"/.well-known",
			"/swagger",
			"/oidc/logout",
		),
	)

	router.RegisterWebRouter(engine, db, m.authCtrl, m.oauth2Ctrl, m.clientCtrl, m.oidcCtrl, m.adminCtrl, m.tokenSvc, m.passkeyCtrl, redis, cfg.WebServerConfig.RateLimits)

	return engine
}

// buildCORSConfig builds CORS configuration from config
func buildCORSConfig(cfg config.GoUnoConfig) cors.Config {
	corsConfig := cors.Config{
		AllowAllOrigins:  false,
		AllowCredentials: cfg.CORSConfig.AllowCredentials,
		MaxAge:           time.Duration(cfg.CORSConfig.MaxAge) * time.Second,
	}
	if len(cfg.CORSConfig.AllowedOrigins) > 0 {
		corsConfig.AllowOrigins = cfg.CORSConfig.AllowedOrigins
	} else {
		corsConfig.AllowOrigins = []string{"http://localhost:8080"}
	}
	if len(cfg.CORSConfig.AllowedMethods) > 0 {
		corsConfig.AllowMethods = cfg.CORSConfig.AllowedMethods
	} else {
		corsConfig.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	}
	if len(cfg.CORSConfig.AllowedHeaders) > 0 {
		corsConfig.AllowHeaders = cfg.CORSConfig.AllowedHeaders
	} else {
		corsConfig.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization"}
	}
	return corsConfig
}
