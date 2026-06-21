package gosso

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/rushairer/gosso/config"
	"github.com/rushairer/gosso/internal/account"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	accountService "github.com/rushairer/gosso/internal/account/service"
	adminController "github.com/rushairer/gosso/internal/admin/controller"
	auditService "github.com/rushairer/gosso/internal/audit/service"
	"github.com/rushairer/gosso/internal/auth"
	authController "github.com/rushairer/gosso/internal/auth/controller"
	authService "github.com/rushairer/gosso/internal/auth/service"
	"github.com/rushairer/gosso/internal/cache"
	notificationService "github.com/rushairer/gosso/internal/notification/service"
	"github.com/rushairer/gosso/internal/oauth2"
	oauth2Controller "github.com/rushairer/gosso/internal/oauth2/controller"
	oauth2Repository "github.com/rushairer/gosso/internal/oauth2/repository"
	oauth2Service "github.com/rushairer/gosso/internal/oauth2/service"
	"github.com/rushairer/gosso/internal/oidc"
	oidcController "github.com/rushairer/gosso/internal/oidc/controller"
	sessionService "github.com/rushairer/gosso/internal/session/service"
	tokenService "github.com/rushairer/gosso/internal/token/service"
	"github.com/rushairer/gosso/internal/utility"
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
	emailSvc         *notificationService.EmailService
}

// initModules initializes all business modules and controllers
func initModules(ctx context.Context, db *sql.DB, redis *cache.RedisClient, logger *zap.Logger, cfg config.GoUnoConfig, auditor *auditService.Auditor) (*appModules, error) {
	accountMod := account.InitializeAccountModule(db, auditor, logger, nil)

	keySvc, err := tokenService.NewKeyService(
		cfg.AuthConfig.PrivateKeyPath,
		cfg.AuthConfig.KeyID,
		cfg.WebServerConfig.Production,
		cfg.AuthConfig.RSAKeyBits,
		logger,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize key service: %w", err)
	}

	blacklistSvc, err := tokenService.NewBlacklistService(redis, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize blacklist service: %w", err)
	}
	tokenSvc, err := tokenService.NewTokenService(
		keySvc,
		cfg.AuthConfig.Issuer,
		cfg.AuthConfig.AccessTokenExpiry,
		cfg.AuthConfig.RefreshTokenExpiry,
		redis,
		blacklistSvc,
		auditor,
		cfg.AuthConfig.EnforceIPBinding,
		logger,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize token service: %w", err)
	}

	providers := buildOAuthProviders(cfg)

	authMod, err := auth.InitializeAuthModule(auth.AuthModuleConfig{
		DB:                    db,
		Redis:                 redis,
		Logger:                logger,
		AuthConfig:            cfg.AuthConfig,
		SMTPConfig:            cfg.SMTPConfig,
		AccountSvc:            accountMod.Service,
		Providers:             providers,
		KeySvc:                keySvc,
		BaseURL:               cfg.AuthConfig.PasswordResetBaseURL,
		Auditor:               auditor,
		TokenSvc:              tokenSvc,
		CredentialRepo:        accountMod.CredentialRepo,
		AccountRepo:           accountMod.AccountRepo,
		RoleRepo:              accountMod.RoleRepo,
		FederatedIdentityRepo: accountMod.FederatedIdentityRepo,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize auth module: %w", err)
	}

	oauth2Mod, err := oauth2.InitializeOAuth2Module(db, redis, logger, cfg.AuthConfig, auditor)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize oauth2 module: %w", err)
	}
	oidcMod := oidc.InitializeOIDCModule(tokenSvc, accountMod.Service, cfg.AuthConfig, authMod.SessionService, accountMod.CredentialRepo, logger)

	// Wire cross-module dependencies into account service via a single atomic call.
	// This replaces the previous three Set* calls that had temporal coupling risks.
	accountMod.Service.SetOptions(&accountService.AccountServiceOptions{
		SessionRevoker:          authMod.SessionService,
		OAuth2ClientDeleter:     &oauth2ClientDeleterAdapter{clientRepo: oauth2Mod.ClientRepo},
		ConsentCacheInvalidator: oauth2Mod.ConsentService,
	})

	authCtrl := authController.NewAuthController(authMod.AuthService, tokenSvc, authMod.SocialLoginService, authMod.VerificationService, authMod.PasswordResetService, !cfg.WebServerConfig.Debug, logger)
	accountValidatorCacheTTL := cfg.AuthConfig.AccountValidatorCacheTTL
	if accountValidatorCacheTTL <= 0 {
		accountValidatorCacheTTL = 5 * time.Second
	}
	oauth2Ctrl, err := oauth2Controller.NewOAuth2ControllerFromConfig(oauth2Controller.OAuth2ControllerConfig{
		ClientSvc:        oauth2Mod.ClientService,
		AuthCodeSvc:      oauth2Mod.AuthCodeService,
		ConsentSvc:       oauth2Mod.ConsentService,
		TokenSvc:         tokenSvc,
		IDTokenSvc:       oidcMod.IDTokenService,
		DeviceCodeSvc:    oauth2Mod.DeviceCodeService,
		ClientAuth:       &oauth2Service.ClientAuthenticator{},
		AccountValidator: newAccountValidatorAdapter(accountMod.Service, logger, accountValidatorCacheTTL),
		SessionValidator: authMod.SessionService,
		Redis:            redis,
		Issuer:           cfg.AuthConfig.Issuer,
		Logger:           logger,
	})
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
		emailSvc:         authMod.EmailService,
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

// accountValidatorCacheEntry holds a cached IsAccountActive result.
type accountValidatorCacheEntry struct {
	active    bool
	expiresAt time.Time
}

// accountValidatorAdapter implements oauth2Controller.AccountValidator using the account service.
// Results are cached for a short TTL to avoid a DB round-trip on every token exchange.
// Expired entries are cleaned up periodically based on elapsed time to prevent unbounded memory growth.
type accountValidatorAdapter struct {
	accountSvc   accountService.AccountService
	logger       *zap.Logger
	cache        sync.Map // map[string]*accountValidatorCacheEntry
	cacheTTL     time.Duration
	lastCleanup  atomic.Int64 // UnixNano timestamp; read/written atomically for lock-free fast-path check
	cacheSize    atomic.Int32 // approximate number of entries in cache; used to enforce max size
	cleanupMutex sync.Mutex
}

// cacheCleanupInterval is how often (in seconds) the cache is scanned for expired entries.
const cacheCleanupInterval = 30 * time.Second

// accountValidatorCacheMaxSize is the maximum number of entries allowed in the cache.
// New entries are dropped when this limit is reached; expired entries are still evicted by cleanup.
const accountValidatorCacheMaxSize = 1024

// newAccountValidatorAdapter creates an accountValidatorAdapter with the lastCleanup timer initialized.
func newAccountValidatorAdapter(svc accountService.AccountService, logger *zap.Logger, ttl time.Duration) *accountValidatorAdapter {
	a := &accountValidatorAdapter{
		accountSvc: svc,
		logger:     logger,
		cacheTTL:   ttl,
	}
	a.lastCleanup.Store(time.Now().UnixNano())
	return a
}

func (a *accountValidatorAdapter) IsAccountActive(ctx context.Context, accountID string) bool {
	// Time-based cleanup of expired entries to prevent unbounded memory growth.
	// lastCleanup is read atomically for the fast-path check; the mutex serializes actual cleanup.
	if time.Since(time.Unix(0, a.lastCleanup.Load())) > cacheCleanupInterval {
		func() {
			a.cleanupMutex.Lock()
			defer a.cleanupMutex.Unlock()
			if time.Since(time.Unix(0, a.lastCleanup.Load())) > cacheCleanupInterval {
				now := time.Now()
				a.cache.Range(func(key, value any) bool {
					if entry, ok := value.(*accountValidatorCacheEntry); ok && now.After(entry.expiresAt) {
						a.cache.Delete(key)
						if v := a.cacheSize.Add(-1); v < 0 {
							a.cacheSize.Store(0)
						}
					}
					return true
				})
				a.lastCleanup.Store(time.Now().UnixNano())
			}
		}()
	}

	// Check cache first.
	replacing := false
	if entry, ok := a.cache.Load(accountID); ok {
		cached := entry.(*accountValidatorCacheEntry)
		if time.Now().Before(cached.expiresAt) {
			return cached.active
		}
		// Expired — evict and fall through to DB lookup.
		// The subsequent store will replace this entry, so no net size change.
		a.cache.Delete(accountID)
		replacing = true
	}

	account, err := a.accountSvc.FindAccountByID(ctx, accountID)
	if err != nil {
		// Fail-closed: log the error for diagnostics rather than silently returning false.
		if a.logger != nil {
			a.logger.Warn("IsAccountActive: failed to look up account, treating as inactive",
				zap.String("account_id", utility.MaskOpaqueID(accountID)), zap.Error(err))
		}
		// Only cache negative results for genuinely missing accounts.
		// Transient DB errors (timeout, connection refused) should NOT be cached
		// to avoid rejecting valid accounts until the cache expires.
		if errors.Is(err, accountRepo.ErrAccountNotFound) {
			if replacing || a.cacheSize.Load() < accountValidatorCacheMaxSize {
				a.cache.Store(accountID, &accountValidatorCacheEntry{
					active:    false,
					expiresAt: time.Now().Add(a.cacheTTL),
				})
				if !replacing {
					a.cacheSize.Add(1)
				}
			}
		}
		return false
	}

	active := account.IsActive()
	if replacing || a.cacheSize.Load() < accountValidatorCacheMaxSize {
		a.cache.Store(accountID, &accountValidatorCacheEntry{
			active:    active,
			expiresAt: time.Now().Add(a.cacheTTL),
		})
		if !replacing {
			a.cacheSize.Add(1)
		}
	}
	return active
}

// oauth2ClientDeleterAdapter implements accountService.OAuth2ClientDeleter using the OAuth2 client repository.
type oauth2ClientDeleterAdapter struct {
	clientRepo oauth2Repository.OAuth2ClientRepository
}

func (a *oauth2ClientDeleterAdapter) SoftDeleteOAuth2ClientsByAccount(ctx context.Context, tx *sql.Tx, accountID string, deletedAt time.Time) error {
	return a.clientRepo.SoftDeleteByAccountID(ctx, tx, accountID, deletedAt)
}
