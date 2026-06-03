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
	AuthService          *service.AuthService
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
		}
	}

	mfaSvc := service.NewMFAService(credentialRepo, db, authConfig.Issuer, logger, passkeySvc)
	if authConfig.TOTPEncryptionKey != "" {
		if err := mfaSvc.SetTOTPEncryptionKey(authConfig.TOTPEncryptionKey); err != nil {
			logger.Error("Failed to set TOTP encryption key", zap.Error(err))
		}
	}

	authSvc := service.NewAuthService(db, accountSvc, sessionSvc, tokenSvc, credentialRepo, roleRepo, redis, logger, auditor, mfaSvc, passkeySvc)

	var socialSvc *service.SocialLoginService
	if len(providers) > 0 {
		socialSvc = service.NewSocialLoginService(db, accountSvc, authSvc, accountRepoImpl, credentialRepo, federatedIdentityRepo, providers, logger)
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
