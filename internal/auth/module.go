package auth

import (
	"database/sql"

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

// InitializeAuthModule initializes the authentication module
func InitializeAuthModule(
	db *sql.DB,
	redis *cache.RedisClient,
	logger *zap.Logger,
	authConfig config.AuthConfig,
	smtpConfig config.SMTPConfig,
	accountSvc accountService.AccountService,
	providers map[string]*service.OAuthProviderConfig,
	keySvc *tokenService.KeyService,
	baseURL string,
	auditor *auditService.Auditor,
	tokenSvc *tokenService.TokenService,
	credentialRepo accountRepo.CredentialRepository,
	accountRepoImpl accountRepo.AccountRepository,
	roleRepo accountRepo.RoleRepository,
	federatedIdentityRepo accountRepo.FederatedIdentityRepository,
) *AuthModule {
	sessionSvc := sessionService.NewSessionService(redis, logger)
	sessionSvc.SetTokenRevoker(tokenSvc)
	if authConfig.SessionTTL > 0 {
		sessionSvc.SetSessionTTL(authConfig.SessionTTL)
	}
	if authConfig.MaxSessions > 0 {
		sessionSvc.SetMaxSessions(authConfig.MaxSessions)
	}

	// PasskeyService (if WebAuthn is configured)
	var passkeySvc *service.PasskeyService
	if authConfig.WebAuthnRPID != "" {
		web, err := wa.New(&wa.Config{
			RPID:          authConfig.WebAuthnRPID,
			RPDisplayName: authConfig.WebAuthnRPName,
			RPOrigins:     []string{authConfig.WebAuthnRPOrigin},
		})
		if err != nil {
			logger.Error("Failed to initialize WebAuthn", zap.Error(err))
		} else {
			webauthnRepo := repository.NewWebAuthnCredentialRepository(db)
			passkeySvc = service.NewPasskeyService(web, webauthnRepo, redis, db, logger)
			if authConfig.ChallengeTTL > 0 {
				passkeySvc.SetChallengeTTL(authConfig.ChallengeTTL)
			}
		}
	}

	mfaSvc := service.NewMFAService(credentialRepo, db, authConfig.Issuer, logger, passkeySvc)
	if authConfig.TOTPEncryptionKey != "" {
		if err := mfaSvc.SetTOTPEncryptionKey(authConfig.TOTPEncryptionKey); err != nil {
			logger.Error("Failed to set TOTP encryption key", zap.Error(err))
		}
	}
	if authConfig.BackupCodeCount > 0 {
		mfaSvc.SetBackupCodeCount(authConfig.BackupCodeCount)
	}
	if authConfig.BackupCodeLength > 0 {
		mfaSvc.SetBackupCodeLength(authConfig.BackupCodeLength)
	}

	authSvc := service.NewAuthService(db, accountSvc, sessionSvc, tokenSvc, credentialRepo, roleRepo, redis, logger, auditor, mfaSvc, passkeySvc)
	if authConfig.LoginRateLimitWindow > 0 {
		authSvc.SetLoginRateLimitWindow(authConfig.LoginRateLimitWindow)
	}
	if authConfig.LoginMaxAttempts > 0 {
		authSvc.SetLoginMaxAttempts(authConfig.LoginMaxAttempts)
	}
	if authConfig.LoginMaxAttemptsPerIP > 0 {
		authSvc.SetLoginMaxAttemptsPerIP(authConfig.LoginMaxAttemptsPerIP)
	}
	if authConfig.MFAVerificationTTL > 0 {
		authSvc.SetMFAVerificationTTL(authConfig.MFAVerificationTTL)
	}

	var socialSvc *service.SocialLoginService
	if len(providers) > 0 {
		socialSvc = service.NewSocialLoginService(db, accountSvc, authSvc, accountRepoImpl, credentialRepo, federatedIdentityRepo, providers, logger)
		socialSvc.SetMFAChecker(authSvc)
		socialSvc.SetAuditor(auditor)
	}

	emailSvc := notificationService.NewEmailService(smtpConfig, logger)
	smsSvc := notificationService.NewStubSMSService(logger)
	verificationSvc := service.NewVerificationService(redis, emailSvc, smsSvc, logger)

	passwordResetSvc := service.NewPasswordResetService(redis, credentialRepo, emailSvc, sessionSvc, accountSvc, db, baseURL, logger)

	return &AuthModule{
		AuthService:          authSvc,
		SocialLoginService:   socialSvc,
		VerificationService:  verificationSvc,
		PasswordResetService: passwordResetSvc,
		CredentialRepo:       credentialRepo,
		PasskeyService:       passkeySvc,
		SessionService:       sessionSvc,
	}
}
