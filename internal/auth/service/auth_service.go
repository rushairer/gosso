package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"runtime"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/semaphore"

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
	// defaultMFAAccountMaxAttempts is the default max MFA verification attempts per account.
	defaultMFAAccountMaxAttempts = 10
	// defaultMFAAccountRateLimitWindow is the default window for per-account MFA rate limiting.
	defaultMFAAccountRateLimitWindow = 5 * time.Minute
)

// LoginCommand represents a username+password login request from the controller layer.
type LoginCommand struct {
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
	MFAToken     string   `json:"-"` // Only set when RequiresMFA is true
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
	loginRateLimitWindow    time.Duration
	loginMaxAttempts        int
	loginMaxAttemptsPerIP   int
	mfaVerificationTTL      time.Duration
	mfaAccountMaxAttempts   int
	mfaAccountRateLimitWindow time.Duration

	// IP allowlist: addresses/ranges exempt from per-IP login rate limiting.
	// Intended for known NAT/proxy exit IPs shared by many legitimate users.
	// Only per-IP limits (login_attempts_ip:{ip}) are skipped; per-IP+username
	// limits (login_attempts:{ip}:{user}) still apply to every address.
	loginIPAllowlist        []*net.IPNet

	// Concurrency limiter for dummy Argon2id hashes to prevent resource exhaustion.
	dummyHashSem *semaphore.Weighted
}

// AuthServiceConfig holds optional configuration for AuthService.
// Zero-valued fields use package defaults.
type AuthServiceConfig struct {
	LoginRateLimitWindow    time.Duration // default: defaultLoginRateLimitWindow
	LoginMaxAttempts        int           // default: defaultLoginMaxAttempts
	LoginMaxAttemptsPerIP   int           // default: defaultLoginMaxAttemptsPerIP
	MFAVerificationTTL      time.Duration // default: defaultMFAVerificationTTL
	MFAAccountMaxAttempts   int           // default: mfaAccountMaxAttempts (10)
	MFAAccountRateLimitWindow time.Duration // default: mfaAccountRateLimitWindow (5min)
	DummyHashConcurrency      int           // max concurrent dummy Argon2id hashes; 0 = runtime.NumCPU()

	// LoginIPAllowlist contains IP addresses or CIDR ranges that are exempt from
	// per-IP login rate limiting (login_attempts_ip:{ip}). Use this for known
	// NAT/proxy exit IPs shared by many legitimate users.
	// Per-IP+username counters (login_attempts:{ip}:{user}) still apply to all addresses.
	LoginIPAllowlist        []string      // e.g. ["203.0.113.0/24", "198.51.100.5"]
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
		loginRateLimitWindow:    defaultLoginRateLimitWindow,
		loginMaxAttempts:        defaultLoginMaxAttempts,
		loginMaxAttemptsPerIP:   defaultLoginMaxAttemptsPerIP,
		mfaVerificationTTL:      defaultMFAVerificationTTL,
		mfaAccountMaxAttempts:   defaultMFAAccountMaxAttempts,
		mfaAccountRateLimitWindow: defaultMFAAccountRateLimitWindow,
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
	if cfg.MFAAccountMaxAttempts > 0 {
		svc.mfaAccountMaxAttempts = cfg.MFAAccountMaxAttempts
	}
	if cfg.MFAAccountRateLimitWindow > 0 {
		svc.mfaAccountRateLimitWindow = cfg.MFAAccountRateLimitWindow
	}
	dummyConcurrency := cfg.DummyHashConcurrency
	if dummyConcurrency <= 0 {
		dummyConcurrency = runtime.NumCPU()
	}
	svc.dummyHashSem = semaphore.NewWeighted(int64(dummyConcurrency))
	if len(cfg.LoginIPAllowlist) > 0 {
		nets, err := parseIPAllowlist(cfg.LoginIPAllowlist)
		if err != nil {
			logger.Warn("Invalid entry in login_ip_allowlist, skipping",
				zap.Error(err))
		} else {
			svc.loginIPAllowlist = nets
		}
	}
	return svc
}

// MFAService returns the MFA service instance
func (s *AuthService) MFAService() *MFAService {
	return s.mfaSvc
}

// VerifyCurrentPassword verifies the current password for the given account.
// Used for step-up authentication before sensitive operations (e.g., disabling MFA).
// Returns nil on success, ErrInvalidCredentials on mismatch.
func (s *AuthService) VerifyCurrentPassword(ctx context.Context, accountID, password string) error {
	if accountID == "" || password == "" {
		return ErrInvalidCredentials
	}
	cred, err := s.credentialRepo.FindPasswordCredential(ctx, accountID)
	if err != nil {
		// Account has no password credential (passkey-only) or not found.
		// Perform dummy work to prevent timing leak — use the semaphore to cap
		// concurrent Argon2id hashes and prevent CPU exhaustion from mass requests.
		if acquireErr := s.dummyHashSem.Acquire(ctx, 1); acquireErr == nil {
			_, _ = accountDomain.HashPassword(password)
			s.dummyHashSem.Release(1)
		} else {
			// Semaphore exhausted (under attack); fall back to sleep-based padding.
			utility.DummyWorkWithContext(ctx)
		}
		return ErrInvalidCredentials
	}
	if !cred.VerifyPassword(password) {
		return ErrInvalidCredentials
	}
	return nil
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
		return fmt.Errorf("%w: %s", ErrUnsupportedCredentialType, credType)
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

// ValidateMFAToken validates MFA token and returns claims.
// Distinguishes system errors (e.g., Redis unavailable) from genuine validation failures
// so callers can retry transient errors rather than rejecting the token outright.
func (s *AuthService) ValidateMFAToken(ctx context.Context, mfaToken string) (*tokenDomain.AccessTokenClaims, error) {
	claims, err := s.tokenSvc.ValidateAccessTokenWithContext(ctx, mfaToken)
	if err != nil {
		// Convert infrastructure errors (e.g., ErrBlacklistUnavailable) to a generic
		// service error so that callers and controller error maps only need to handle
		// auth-layer sentinel errors, not token-layer internals.
		if errors.Is(err, tokenService.ErrBlacklistUnavailable) {
			return nil, ErrServiceUnavailable
		}
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

// parseIPAllowlist parses a list of IP addresses and CIDR ranges into []*net.IPNet.
// Individual IP addresses (e.g. "198.51.100.5") are converted to /32 or /128 masks.
// Returns the first parse error encountered.
func parseIPAllowlist(entries []string) ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0, len(entries))
	for _, entry := range entries {
		if ip := net.ParseIP(entry); ip != nil {
			// Single IP address — wrap in a /32 (v4) or /128 (v6) network.
			if ip.To4() != nil {
				nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)})
			} else {
				nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
			}
			continue
		}
		_, ipNet, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("parse IP allowlist entry %q: %w", entry, err)
		}
		nets = append(nets, ipNet)
	}
	return nets, nil
}
