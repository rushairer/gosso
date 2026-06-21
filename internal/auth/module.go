package auth

import (
	"database/sql"
	"fmt"

	wa "github.com/go-webauthn/webauthn/webauthn"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/config"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	accountService "github.com/rushairer/gosso/internal/account/service"
	auditService "github.com/rushairer/gosso/internal/audit/service"
	"github.com/rushairer/gosso/internal/auth/repository"
	"github.com/rushairer/gosso/internal/auth/service"
	"github.com/rushairer/gosso/internal/cache"
	notificationService "github.com/rushairer/gosso/internal/notification/service"
	sessionService "github.com/rushairer/gosso/internal/session/service"
	tokenService "github.com/rushairer/gosso/internal/token/service"
)

// AuthModule holds all services and repositories for the authentication module.
type AuthModule struct {
	AuthService          service.AuthOrchestrator
	SocialLoginService   *service.SocialLoginService
	VerificationService  *service.VerificationService
	PasswordResetService *service.PasswordResetService
	CredentialRepo       accountRepo.CredentialRepository
	PasskeyService       *service.PasskeyService
	SessionService       *sessionService.SessionService
	EmailService         *notificationService.EmailService
}

// AuthModuleConfig holds all dependencies for initializing the authentication module.
type AuthModuleConfig struct {
	DB                    *sql.DB
	Redis                 *cache.RedisClient
	Logger                *zap.Logger
	AuthConfig            config.AuthConfig
	SMTPConfig            config.SMTPConfig
	AccountSvc            accountService.AccountService
	Providers             map[string]*service.OAuthProviderConfig
	KeySvc                *tokenService.KeyService
	BaseURL               string
	Auditor               *auditService.Auditor
	TokenSvc              *tokenService.TokenService
	CredentialRepo        accountRepo.CredentialRepository
	AccountRepo           accountRepo.AccountRepository
	RoleRepo              accountRepo.RoleRepository
	FederatedIdentityRepo accountRepo.FederatedIdentityRepository
}

// InitializeAuthModule initializes the authentication module.
// Returns an error if the TOTP encryption key cannot be set.
func InitializeAuthModule(cfg AuthModuleConfig) (*AuthModule, error) {
	sessionSvc, err := sessionService.NewSessionServiceWithConfig(cfg.Redis, cfg.Logger, sessionService.SessionConfig{
		SessionTTL:    cfg.AuthConfig.SessionTTL,
		MaxSessions:   cfg.AuthConfig.MaxSessions,
		MaxSessionAge: cfg.AuthConfig.MaxSessionAge,
		TokenRevoker:  cfg.TokenSvc,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize session service: %w", err)
	}

	// PasskeyService (if WebAuthn is configured)
	var passkeySvc *service.PasskeyService
	if cfg.AuthConfig.WebAuthnRPID != "" {
		web, err := wa.New(&wa.Config{
			RPID:          cfg.AuthConfig.WebAuthnRPID,
			RPDisplayName: cfg.AuthConfig.WebAuthnRPName,
			RPOrigins:     []string{cfg.AuthConfig.WebAuthnRPOrigin},
		})
		if err != nil {
			cfg.Logger.Error("Failed to initialize WebAuthn", zap.Error(err),
				zap.String("rp_id", cfg.AuthConfig.WebAuthnRPID))
			cfg.Logger.Warn("Passkey/WebAuthn functionality will be unavailable; server will continue without it")
		} else {
			webauthnRepo := repository.NewWebAuthnCredentialRepository(cfg.DB)
			passkeySvc = service.NewPasskeyServiceWithConfig(web, webauthnRepo, cfg.Redis, cfg.DB, cfg.AccountSvc, cfg.Logger, service.PasskeyServiceConfig{
				ChallengeTTL: cfg.AuthConfig.ChallengeTTL,
			})
		}
	}

	mfaSvc, err := service.NewMFAServiceWithConfig(cfg.CredentialRepo, cfg.DB, cfg.AuthConfig.Issuer, cfg.Logger, service.MFAServiceConfig{
		TOTPEncryptionKey: cfg.AuthConfig.TOTPEncryptionKey,
		BackupCodeCount:   cfg.AuthConfig.BackupCodeCount,
		BackupCodeLength:  cfg.AuthConfig.BackupCodeLength,
	}, passkeySvc)
	if err != nil {
		return nil, fmt.Errorf("initialize MFA service: %w", err)
	}

	authSvc := service.NewAuthServiceWithConfig(cfg.DB, cfg.AccountSvc, sessionSvc, cfg.TokenSvc, cfg.CredentialRepo, cfg.RoleRepo, cfg.Redis, cfg.Logger, cfg.Auditor, mfaSvc, passkeySvc, service.AuthServiceConfig{
		LoginRateLimitWindow:      cfg.AuthConfig.LoginRateLimitWindow,
		LoginMaxAttempts:          cfg.AuthConfig.LoginMaxAttempts,
		LoginMaxAttemptsPerIP:     cfg.AuthConfig.LoginMaxAttemptsPerIP,
		LoginIPAllowlist:          cfg.AuthConfig.LoginIPAllowlist,
		MFAVerificationTTL:        cfg.AuthConfig.MFAVerificationTTL,
		MFAAccountMaxAttempts:     cfg.AuthConfig.MFAAccountMaxAttempts,
		MFAAccountRateLimitWindow: cfg.AuthConfig.MFAAccountRateLimitWindow,
	})

	var socialSvc *service.SocialLoginService
	var socialErr error
	if len(cfg.Providers) > 0 {
		// authSvc implements both SessionTokenCreator (3rd arg) and MFAChecker (9th arg).
		socialSvc, socialErr = service.NewSocialLoginService(cfg.DB, cfg.AccountSvc, authSvc, cfg.AccountRepo, cfg.CredentialRepo, cfg.FederatedIdentityRepo, cfg.Providers, cfg.Logger, authSvc, cfg.Auditor, cfg.AuthConfig.SocialLoginHTTPTimeout)
		if socialErr != nil {
			return nil, fmt.Errorf("initialize social login service: %w", socialErr)
		}
	}

	emailSvc, err := notificationService.NewEmailService(cfg.SMTPConfig, cfg.Logger)
	if err != nil {
		return nil, fmt.Errorf("initialize email service: %w", err)
	}
	if cfg.SMTPConfig.SendRateLimit > 0 {
		emailSvc.SetSendRateLimit(cfg.SMTPConfig.SendRateLimit)
	}
	if cfg.AuthConfig.VerifyCodeTTL > 0 {
		emailSvc.SetVerifyCodeTTL(cfg.AuthConfig.VerifyCodeTTL)
	}
	if cfg.AuthConfig.PasswordResetTokenTTL > 0 {
		emailSvc.SetPasswordResetTTL(cfg.AuthConfig.PasswordResetTokenTTL)
	}
	smsSvc := notificationService.NewStubSMSService(cfg.Logger)
	verificationSvc := service.NewVerificationServiceWithConfig(cfg.Redis, emailSvc, smsSvc, cfg.CredentialRepo, cfg.Logger, service.VerificationServiceConfig{
		CodeTTL:     cfg.AuthConfig.VerifyCodeTTL,
		CooldownTTL: cfg.AuthConfig.VerifyCooldownTTL,
		MaxAttempts: cfg.AuthConfig.VerifyCodeMaxAttempts,
		HashPepper:  cfg.AuthConfig.VerifyHashPepper,
	})

	passwordResetSvc := service.NewPasswordResetServiceWithConfig(cfg.Redis, cfg.CredentialRepo, emailSvc, sessionSvc, cfg.TokenSvc, cfg.AccountSvc, cfg.DB, cfg.BaseURL, cfg.Logger, service.PasswordResetServiceConfig{
		WaitTimeout:          cfg.AuthConfig.PasswordResetWaitTimeout,
		TokenTTL:             cfg.AuthConfig.PasswordResetTokenTTL,
		CooldownTTL:          cfg.AuthConfig.PasswordResetCooldownTTL,
		MaxAttempts:          cfg.AuthConfig.PasswordResetMaxAttempts,
		RevokeConcurrency:    cfg.AuthConfig.PasswordResetRevokeConcurrency,
		LoginRateLimitClearer: authSvc,
		Auditor:              cfg.Auditor,
	})

	return &AuthModule{
		AuthService:          authSvc,
		SocialLoginService:   socialSvc,
		VerificationService:  verificationSvc,
		PasswordResetService: passwordResetSvc,
		CredentialRepo:       cfg.CredentialRepo,
		PasskeyService:       passkeySvc,
		SessionService:       sessionSvc,
		EmailService:         emailSvc,
	}, nil
}
