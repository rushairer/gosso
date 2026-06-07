package gouno

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/rushairer/gosso/config"
	"github.com/rushairer/gosso/internal/account"
	accountService "github.com/rushairer/gosso/internal/account/service"
	adminController "github.com/rushairer/gosso/internal/admin/controller"
	auditService "github.com/rushairer/gosso/internal/audit/service"
	"github.com/rushairer/gosso/internal/auth"
	authController "github.com/rushairer/gosso/internal/auth/controller"
	authService "github.com/rushairer/gosso/internal/auth/service"
	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/oauth2"
	oauth2Controller "github.com/rushairer/gosso/internal/oauth2/controller"
	oauth2Repository "github.com/rushairer/gosso/internal/oauth2/repository"
	"github.com/rushairer/gosso/internal/oidc"
	oidcController "github.com/rushairer/gosso/internal/oidc/controller"
	sessionService "github.com/rushairer/gosso/internal/session/service"
	tokenService "github.com/rushairer/gosso/internal/token/service"
)

// appModules aggregates all initialized modules and controllers
type appModules struct {
	authCtrl         *authController.AuthController
	oauth2Ctrl       *oauth2Controller.OAuth2Controller
	clientCtrl       *oauth2Controller.ClientController
	oidcCtrl         *oidcController.OIDCController
	adminCtrl        *adminController.AdminController
	passkeyCtrl      *authController.PasskeyController
	tokenSvc         *tokenService.TokenService
	sessionSvc       *sessionService.SessionService
	passwordResetSvc *authService.PasswordResetService
}

// initModules initializes all business modules and controllers
func initModules(ctx context.Context, db *sql.DB, redis *cache.RedisClient, logger *zap.Logger, cfg config.GoUnoConfig, auditor *auditService.Auditor) (*appModules, error) {
	accountMod := account.InitializeAccountModule(db, auditor, logger)

	keySvc, err := tokenService.NewKeyService(
		cfg.AuthConfig.PrivateKeyPath,
		cfg.AuthConfig.KeyID,
		logger,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize key service: %w", err)
	}

	blacklistSvc := tokenService.NewBlacklistService(redis, logger)
	tokenSvc := tokenService.NewTokenService(
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
		db, redis, logger, cfg.AuthConfig, cfg.SMTPConfig, accountMod.Service, providers, keySvc, cfg.AuthConfig.PasswordResetBaseURL, auditor, tokenSvc,
		accountMod.CredentialRepo, accountMod.AccountRepo, accountMod.RoleRepo, accountMod.FederatedIdentityRepo,
	)

	// Wire session revoker into account service (for account deletion -> session revocation)
	accountService.BindSessionRevoker(accountMod.Service, authMod.SessionService)

	oauth2Mod := oauth2.InitializeOAuth2Module(db, redis, logger, cfg.AuthConfig)
	oidcMod := oidc.InitializeOIDCModule(tokenSvc, accountMod.Service, cfg.AuthConfig, authMod.SessionService, accountMod.CredentialRepo, logger)

	// Wire OAuth2 client deleter into account service (for account deletion -> OAuth2 client cascade)
	accountService.BindOAuth2ClientDeleter(accountMod.Service, &oauth2ClientDeleterAdapter{clientRepo: oauth2Mod.ClientRepo})

	authCtrl := authController.NewAuthController(authMod.AuthService, tokenSvc, authMod.SocialLoginService, authMod.VerificationService, authMod.PasswordResetService, !cfg.WebServerConfig.Debug, logger)
	oauth2Ctrl, err := oauth2Controller.NewOAuth2Controller(oauth2Mod.ClientService, oauth2Mod.AuthCodeService, oauth2Mod.ConsentService, tokenSvc, oidcMod.IDTokenService, oauth2Mod.DeviceCodeService, &accountValidatorAdapter{accountSvc: accountMod.Service}, authMod.SessionService, cfg.AuthConfig.Issuer, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize OAuth2 controller: %w", err)
	}
	clientCtrl := oauth2Controller.NewClientController(oauth2Mod.ClientService, logger)
	oidcCtrl := oidcController.NewOIDCController(oidcMod.DiscoveryService, oidcMod.JWKSService, oidcMod.UserInfoService, oidcMod.LogoutService, oauth2Mod.ClientRepo, tokenSvc, authMod.SessionService, cfg.AuthConfig.Issuer, logger)
	adminCtrl := adminController.NewAdminController(accountMod.Service, logger)

	var passkeyCtrl *authController.PasskeyController
	if authMod.PasskeyService != nil {
		passkeyCtrl = authController.NewPasskeyController(authMod.PasskeyService, authMod.AuthService, tokenSvc, logger)
	}

	return &appModules{
		authCtrl:         authCtrl,
		oauth2Ctrl:       oauth2Ctrl,
		clientCtrl:       clientCtrl,
		oidcCtrl:         oidcCtrl,
		adminCtrl:        adminCtrl,
		passkeyCtrl:      passkeyCtrl,
		tokenSvc:         tokenSvc,
		sessionSvc:       authMod.SessionService,
		passwordResetSvc: authMod.PasswordResetService,
	}, nil
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

// accountValidatorAdapter implements oauth2Controller.AccountValidator using the account service.
type accountValidatorAdapter struct {
	accountSvc accountService.AccountService
}

func (a *accountValidatorAdapter) IsAccountActive(ctx context.Context, accountID string) bool {
	account, err := a.accountSvc.FindAccountByID(ctx, accountID)
	if err != nil {
		return false
	}
	return account.IsActive()
}

// oauth2ClientDeleterAdapter implements accountService.OAuth2ClientDeleter using the OAuth2 client repository.
type oauth2ClientDeleterAdapter struct {
	clientRepo oauth2Repository.OAuth2ClientRepository
}

func (a *oauth2ClientDeleterAdapter) SoftDeleteOAuth2ClientsByAccount(ctx context.Context, tx *sql.Tx, accountID string, deletedAt time.Time) error {
	return a.clientRepo.SoftDeleteByAccountID(ctx, tx, accountID, deletedAt)
}
