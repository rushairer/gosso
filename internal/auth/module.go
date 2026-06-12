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
	sessionSvc := sessionService.NewSessionService(cfg.Redis, cfg.Logger)
	sessionSvc.SetTokenRevoker(cfg.TokenSvc)
	if cfg.AuthConfig.SessionTTL > 0 {
		sessionSvc.SetSessionTTL(cfg.AuthConfig.SessionTTL)
	}
	if cfg.AuthConfig.MaxSessions > 0 {
		sessionSvc.SetMaxSessions(cfg.AuthConfig.MaxSessions)
	}
	if cfg.AuthConfig.MaxSessionAge > 0 {
		sessionSvc.SetMaxSessionAge(cfg.AuthConfig.MaxSessionAge)
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
			cfg.Logger.Error("Failed to initialize WebAuthn", zap.Error(err))
		} else {
			webauthnRepo := repository.NewWebAuthnCredentialRepository(cfg.DB)
			passkeySvc = service.NewPasskeyService(web, webauthnRepo, cfg.Redis, cfg.DB, cfg.AccountSvc, cfg.Logger)
			if cfg.AuthConfig.ChallengeTTL > 0 {
				passkeySvc.SetChallengeTTL(cfg.AuthConfig.ChallengeTTL)
			}
		}
	}

	mfaSvc := service.NewMFAService(cfg.CredentialRepo, cfg.DB, cfg.AuthConfig.Issuer, cfg.Logger, passkeySvc)
	if cfg.AuthConfig.TOTPEncryptionKey != "" {
		if err := mfaSvc.SetTOTPEncryptionKey(cfg.AuthConfig.TOTPEncryptionKey); err != nil {
			return nil, fmt.Errorf("failed to set TOTP encryption key: %w", err)
		}
	}
	if cfg.AuthConfig.BackupCodeCount > 0 {
		mfaSvc.SetBackupCodeCount(cfg.AuthConfig.BackupCodeCount)
	}
	if cfg.AuthConfig.BackupCodeLength > 0 {
		mfaSvc.SetBackupCodeLength(cfg.AuthConfig.BackupCodeLength)
	}

	authSvc := service.NewAuthService(cfg.DB, cfg.AccountSvc, sessionSvc, cfg.TokenSvc, cfg.CredentialRepo, cfg.RoleRepo, cfg.Redis, cfg.Logger, cfg.Auditor, mfaSvc, passkeySvc)
	if cfg.AuthConfig.LoginRateLimitWindow > 0 {
		authSvc.SetLoginRateLimitWindow(cfg.AuthConfig.LoginRateLimitWindow)
	}
	if cfg.AuthConfig.LoginMaxAttempts > 0 {
		authSvc.SetLoginMaxAttempts(cfg.AuthConfig.LoginMaxAttempts)
	}
	if cfg.AuthConfig.LoginMaxAttemptsPerIP > 0 {
		authSvc.SetLoginMaxAttemptsPerIP(cfg.AuthConfig.LoginMaxAttemptsPerIP)
	}
	if cfg.AuthConfig.MFAVerificationTTL > 0 {
		authSvc.SetMFAVerificationTTL(cfg.AuthConfig.MFAVerificationTTL)
	}

	var socialSvc *service.SocialLoginService
	if len(cfg.Providers) > 0 {
		socialSvc = service.NewSocialLoginService(cfg.DB, cfg.AccountSvc, authSvc, cfg.AccountRepo, cfg.CredentialRepo, cfg.FederatedIdentityRepo, cfg.Providers, cfg.Logger)
		socialSvc.SetMFAChecker(authSvc)
		socialSvc.SetAuditor(cfg.Auditor)
	}

	emailSvc := notificationService.NewEmailService(cfg.SMTPConfig, cfg.Logger)
	if cfg.AuthConfig.VerifyCodeTTL > 0 {
		emailSvc.SetVerifyCodeTTL(cfg.AuthConfig.VerifyCodeTTL)
	}
	if cfg.AuthConfig.PasswordResetTokenTTL > 0 {
		emailSvc.SetPasswordResetTTL(cfg.AuthConfig.PasswordResetTokenTTL)
	}
	smsSvc := notificationService.NewStubSMSService(cfg.Logger)
	verificationSvc := service.NewVerificationService(cfg.Redis, emailSvc, smsSvc, cfg.CredentialRepo, cfg.Logger)
	if cfg.AuthConfig.VerifyCodeTTL > 0 {
		verificationSvc.SetCodeTTL(cfg.AuthConfig.VerifyCodeTTL)
	}
	if cfg.AuthConfig.VerifyCooldownTTL > 0 {
		verificationSvc.SetCooldownTTL(cfg.AuthConfig.VerifyCooldownTTL)
	}
	if cfg.AuthConfig.VerifyCodeMaxAttempts > 0 {
		verificationSvc.SetMaxAttempts(cfg.AuthConfig.VerifyCodeMaxAttempts)
	}

	passwordResetSvc := service.NewPasswordResetService(cfg.Redis, cfg.CredentialRepo, emailSvc, sessionSvc, cfg.TokenSvc, cfg.AccountSvc, cfg.DB, cfg.BaseURL, cfg.Logger)
	if cfg.AuthConfig.PasswordResetWaitTimeout > 0 {
		passwordResetSvc.SetWaitTimeout(cfg.AuthConfig.PasswordResetWaitTimeout)
	}
	if cfg.AuthConfig.PasswordResetTokenTTL > 0 {
		passwordResetSvc.SetTokenTTL(cfg.AuthConfig.PasswordResetTokenTTL)
	}
	if cfg.AuthConfig.PasswordResetCooldownTTL > 0 {
		passwordResetSvc.SetCooldownTTL(cfg.AuthConfig.PasswordResetCooldownTTL)
	}
	if cfg.AuthConfig.PasswordResetMaxAttempts > 0 {
		passwordResetSvc.SetMaxAttempts(cfg.AuthConfig.PasswordResetMaxAttempts)
	}

	return &AuthModule{
		AuthService:          authSvc,
		SocialLoginService:   socialSvc,
		VerificationService:  verificationSvc,
		PasswordResetService: passwordResetSvc,
		CredentialRepo:       cfg.CredentialRepo,
		PasskeyService:       passkeySvc,
		SessionService:       sessionSvc,
	}, nil
}
