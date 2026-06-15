package service

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	accountService "github.com/rushairer/gosso/internal/account/service"
	auditService "github.com/rushairer/gosso/internal/audit/service"
	"github.com/rushairer/gosso/internal/cache"
	dbutil "github.com/rushairer/gosso/internal/db"
	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
	sessionService "github.com/rushairer/gosso/internal/session/service"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	tokenService "github.com/rushairer/gosso/internal/token/service"
	"github.com/rushairer/gosso/internal/utility"
)

const (
	// defaultMFAVerificationTTL is the default TTL for the passkey MFA verification flag in Redis.
	defaultMFAVerificationTTL = 5 * time.Minute
	// defaultLoginRateLimitWindow is the default window for login rate limiting.
	defaultLoginRateLimitWindow = 15 * time.Minute
	// defaultLoginMaxAttempts is the default max login attempts per username+IP.
	defaultLoginMaxAttempts = 5
	// defaultLoginMaxAttemptsPerIP is the default max login attempts per IP.
	defaultLoginMaxAttemptsPerIP = 30
)

// LoginRequest login request
type LoginRequest struct {
	Username  string
	Password  string
	IP        string
	UserAgent string
}

// LoginResult login result
type LoginResult struct {
	Account      *accountDomain.Account
	Session      *sessionDomain.Session
	AccessToken  string
	RefreshToken string
	RequiresMFA  bool
	MFATypes     []string `json:"mfa_types,omitempty"`
}

// RefreshResult refresh token result
type RefreshResult struct {
	AccessToken  string
	RefreshToken string
	SessionID    string
}

// AuthService authentication orchestration service
type AuthService struct {
	db             *sql.DB
	accountSvc     accountService.AccountService
	sessionSvc     *sessionService.SessionService
	tokenSvc       *tokenService.TokenService
	credentialRepo accountRepo.CredentialRepository
	roleRepo       accountRepo.RoleRepository
	redis          *cache.RedisClient
	mfaSvc         *MFAService
	passkeySvc     *PasskeyService
	auditor        *auditService.Auditor
	logger         *zap.Logger

	// Configurable security parameters (with built-in defaults)
	loginRateLimitWindow  time.Duration
	loginMaxAttempts      int
	loginMaxAttemptsPerIP int
	mfaVerificationTTL    time.Duration
}

// AuthServiceConfig holds optional configuration for AuthService.
// Zero-valued fields use package defaults.
type AuthServiceConfig struct {
	LoginRateLimitWindow  time.Duration // default: defaultLoginRateLimitWindow
	LoginMaxAttempts      int           // default: defaultLoginMaxAttempts
	LoginMaxAttemptsPerIP int           // default: defaultLoginMaxAttemptsPerIP
	MFAVerificationTTL    time.Duration // default: defaultMFAVerificationTTL
}

// NewAuthService creates a new auth service instance
func NewAuthService(
	db *sql.DB,
	accountSvc accountService.AccountService,
	sessionSvc *sessionService.SessionService,
	tokenSvc *tokenService.TokenService,
	credentialRepo accountRepo.CredentialRepository,
	roleRepo accountRepo.RoleRepository,
	redis *cache.RedisClient,
	logger *zap.Logger,
	auditor *auditService.Auditor,
	mfaSvc *MFAService,
	passkeySvc *PasskeyService,
) *AuthService {
	return NewAuthServiceWithConfig(db, accountSvc, sessionSvc, tokenSvc, credentialRepo, roleRepo, redis, logger, auditor, mfaSvc, passkeySvc, AuthServiceConfig{})
}

// NewAuthServiceWithConfig creates a new auth service instance with the given config.
// Zero-valued config fields use package defaults.
func NewAuthServiceWithConfig(
	db *sql.DB,
	accountSvc accountService.AccountService,
	sessionSvc *sessionService.SessionService,
	tokenSvc *tokenService.TokenService,
	credentialRepo accountRepo.CredentialRepository,
	roleRepo accountRepo.RoleRepository,
	redis *cache.RedisClient,
	logger *zap.Logger,
	auditor *auditService.Auditor,
	mfaSvc *MFAService,
	passkeySvc *PasskeyService,
	cfg AuthServiceConfig,
) *AuthService {
	logger = utility.EnsureLogger(logger)
	svc := &AuthService{
		db:                    db,
		accountSvc:            accountSvc,
		sessionSvc:            sessionSvc,
		tokenSvc:              tokenSvc,
		credentialRepo:        credentialRepo,
		roleRepo:              roleRepo,
		redis:                 redis,
		mfaSvc:                mfaSvc,
		auditor:               auditor,
		logger:                logger,
		passkeySvc:            passkeySvc,
		loginRateLimitWindow:  defaultLoginRateLimitWindow,
		loginMaxAttempts:      defaultLoginMaxAttempts,
		loginMaxAttemptsPerIP: defaultLoginMaxAttemptsPerIP,
		mfaVerificationTTL:    defaultMFAVerificationTTL,
	}
	if cfg.LoginRateLimitWindow > 0 {
		svc.loginRateLimitWindow = cfg.LoginRateLimitWindow
	}
	if cfg.LoginMaxAttempts > 0 {
		svc.loginMaxAttempts = cfg.LoginMaxAttempts
	}
	if cfg.LoginMaxAttemptsPerIP > 0 {
		svc.loginMaxAttemptsPerIP = cfg.LoginMaxAttemptsPerIP
	}
	if cfg.MFAVerificationTTL > 0 {
		svc.mfaVerificationTTL = cfg.MFAVerificationTTL
	}
	return svc
}

// MFAService returns the MFA service instance
func (s *AuthService) MFAService() *MFAService {
	return s.mfaSvc
}

// ConfirmVerificationCredential confirms a verification code and marks the credential as verified.
// It verifies that the credential belongs to the specified account before updating.
func (s *AuthService) ConfirmVerificationCredential(ctx context.Context, credType, identifier, accountID string) error {
	var domainCredType accountDomain.CredentialType
	switch credType {
	case "email":
		domainCredType = accountDomain.CredentialTypeEmail
	case "phone":
		domainCredType = accountDomain.CredentialTypePhone
	default:
		return fmt.Errorf("unsupported credential type: %s", credType)
	}

	return dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		// Find inside the transaction to avoid TOCTOU: the credential could have been
		// modified or deleted between the original find and this update.
		cred, err := s.credentialRepo.FindByTypeAndIdentifierTx(ctx, tx, domainCredType, identifier)
		if err != nil {
			return fmt.Errorf("find credential: %w", err)
		}
		if cred.AccountID != accountID {
			return ErrCredentialOwnership
		}
		cred.Verify()
		return s.credentialRepo.UpdateCredential(ctx, tx, cred)
	})
}

// PasskeyService returns the Passkey service instance
func (s *AuthService) PasskeyService() *PasskeyService {
	return s.passkeySvc
}

// TokenService returns the Token service instance
func (s *AuthService) TokenService() *tokenService.TokenService {
	return s.tokenSvc
}

// ValidateMFAToken validates MFA token and returns claims
func (s *AuthService) ValidateMFAToken(ctx context.Context, mfaToken string) (*tokenDomain.AccessTokenClaims, error) {
	claims, err := s.tokenSvc.ValidateAccessTokenWithContext(ctx, mfaToken)
	if err != nil {
		return nil, ErrInvalidMFAToken
	}
	if claims.Scope != ScopeMFA {
		return nil, ErrInvalidMFATokenScope
	}
	return claims, nil
}

// MarkPasskeyMFAVerified marks passkey MFA as verified for a specific MFA attempt.
// The key is namespaced by the MFA token JTI to prevent concurrent login interference.
func (s *AuthService) MarkPasskeyMFAVerified(ctx context.Context, mfaTokenJTI string) error {
	key := fmt.Sprintf("webauthn:mfa_verified:%s", mfaTokenJTI)
	return s.redis.Set(ctx, key, "1", s.mfaVerificationTTL)
}

// SetLoginRateLimitWindow overrides the login rate limit window (for config-driven setup).
// Must be called during initialization; not safe for concurrent use.
func (s *AuthService) SetLoginRateLimitWindow(d time.Duration) {
	if d > 0 {
		s.loginRateLimitWindow = d
	}
}

// SetLoginMaxAttempts overrides the max login attempts per username+IP.
// Must be called during initialization; not safe for concurrent use.
func (s *AuthService) SetLoginMaxAttempts(n int) {
	if n > 0 {
		s.loginMaxAttempts = n
	}
}

// SetLoginMaxAttemptsPerIP overrides the max login attempts per IP.
// Must be called during initialization; not safe for concurrent use.
func (s *AuthService) SetLoginMaxAttemptsPerIP(n int) {
	if n > 0 {
		s.loginMaxAttemptsPerIP = n
	}
}

// SetMFAVerificationTTL overrides the MFA verification flag TTL.
// Must be called during initialization; not safe for concurrent use.
func (s *AuthService) SetMFAVerificationTTL(d time.Duration) {
	if d > 0 {
		s.mfaVerificationTTL = d
	}
}

// updateCredentialLastUsed updates only the last_used_at timestamp of a credential.
// Uses UpdateLastUsedAt to avoid overwriting concurrent modifications to other fields.
func (s *AuthService) updateCredentialLastUsed(ctx context.Context, cred *accountDomain.Credential) error {
	now := time.Now()
	return dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.credentialRepo.UpdateLastUsedAt(ctx, tx, cred.ID, now)
	})
}

// buildTokenClaims fetches roles and permissions for an account and builds token claims.
func (s *AuthService) buildTokenClaims(ctx context.Context, accountID, sessionID string) (*tokenDomain.AccessTokenClaims, error) {
	roles, err := s.roleRepo.FindRolesByAccountID(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("fetch roles for token: %w", err)
	}

	var roleNames []string
	roleSet := make(map[string]struct{})
	permSet := make(map[string]struct{})
	var allPermissions []string
	for _, role := range roles {
		if _, exists := roleSet[role.Name]; !exists {
			roleSet[role.Name] = struct{}{}
			roleNames = append(roleNames, role.Name)
		}
		for _, p := range role.Permissions {
			if _, exists := permSet[p]; !exists {
				permSet[p] = struct{}{}
				allPermissions = append(allPermissions, p)
			}
		}
	}

	return &tokenDomain.AccessTokenClaims{
		AccountID:   accountID,
		Roles:       roleNames,
		Permissions: allPermissions,
		SessionID:   sessionID,
	}, nil
}
