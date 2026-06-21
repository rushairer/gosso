package service

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	accountService "github.com/rushairer/gosso/internal/account/service"
	"github.com/rushairer/gosso/internal/audit"
	auditDomain "github.com/rushairer/gosso/internal/audit/domain"
	auditService "github.com/rushairer/gosso/internal/audit/service"
	"github.com/rushairer/gosso/internal/cache"
	dbutil "github.com/rushairer/gosso/internal/db"
	sessionService "github.com/rushairer/gosso/internal/session/service"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	"github.com/rushairer/gosso/internal/utility"
)

const (
	passwordResetTokenKeyPrefix    = "password_reset:token:"
	passwordResetCooldownPrefix    = "password_reset:cooldown:"
	passwordResetTokenLength       = 32
	passwordResetTokenTTL          = 30 * time.Minute
	passwordResetCooldownTTL       = 60 * time.Second
	passwordResetMaxAttempts       = 5
	passwordResetRevokeTimeout     = 30 * time.Second
	passwordResetSyncRevokeTimeout = 5 * time.Second
)

// checkAndIncrementAttemptsScript atomically checks attempt count, increments, and returns the data.
// Returns: data string on success, -1 if exhausted (key deleted), nil if key not found.
// Uses cjson.decode for robust JSON parsing when available (real Redis), falling back
// to string pattern matching for environments without cjson (e.g., miniredis in tests).
var checkAndIncrementAttemptsScript = redis.NewScript(`
local data = redis.call('GET', KEYS[1])
if not data then
    return nil
end
local max_attempts = tonumber(ARGV[1])
local attempts
local account_id, email, username
local cjson_ok, cjson = pcall(require, 'cjson')
if cjson_ok then
    local ok, obj = pcall(cjson.decode, data)
    if ok and obj then
        attempts = obj.attempts
        account_id = obj.account_id
        email = obj.email
        username = obj.username
    end
end
if not attempts then
    attempts = tonumber(data:match('"attempts":(%d+)')) or 0
    if not account_id then
        account_id = data:match('"account_id":"([^"]*)"')
    end
    if not email then
        email = data:match('"email":"([^"]*)"')
    end
    if not username then
        username = data:match('"username":"([^"]*)"')
    end
end
if attempts >= max_attempts then
    redis.call('DEL', KEYS[1])
    return -1
end
local updated
if cjson_ok then
    local obj = {account_id = account_id or '', email = email or '', username = username or '', attempts = attempts + 1}
    updated = cjson.encode(obj)
else
    updated = data:gsub('"attempts":' .. attempts, '"attempts":' .. (attempts + 1))
end
redis.call('SETEX', KEYS[1], ARGV[2], updated)
return updated
`)

// PasswordResetEmailSender abstracts email delivery for password-reset links.
// Implementations must not leak whether the address is registered.
type PasswordResetEmailSender interface {
	SendPasswordResetLink(ctx context.Context, to, resetLink string) error
}

// AccountTokenRevoker abstracts account-level token revocation.
// Implementations blacklist all access tokens issued before the revocation timestamp.
type AccountTokenRevoker interface {
	RevokeAccountTokens(ctx context.Context, accountID string) error
}

// LoginRateLimitClearer clears login rate-limit counters for a given username.
// Used after successful password reset to unblock accounts locked by brute-force attacks.
type LoginRateLimitClearer interface {
	ClearLoginRateLimitsByUsername(ctx context.Context, username string) error
}

type passwordResetData struct {
	AccountID string `json:"account_id"`
	// Email is stored to avoid an extra DB round-trip during VerifyAndReset.
	// The token key is a SHA-256 hash, so the Redis value is not guessable.
	// The TTL ensures automatic cleanup.
	Email    string `json:"email"`
	// Username is stored so that ClearLoginRateLimitsByUsername can match
	// the login rate-limit keys (which are keyed on username, not email).
	Username string `json:"username,omitempty"`
	Attempts int    `json:"attempts"`
}

// PasswordResetService password reset service
type PasswordResetService struct {
	redis                 *cache.RedisClient
	credentialRepo        accountRepo.CredentialRepository
	emailSender           PasswordResetEmailSender
	sessionSvc            *sessionService.SessionService
	tokenRevoker          AccountTokenRevoker
	accountSvc            accountService.AccountService
	loginRateLimitClearer LoginRateLimitClearer
	auditor               *auditService.Auditor
	db                    *sql.DB
	baseURL               string
	logger                *zap.Logger
	wg                    sync.WaitGroup
	revokeSem             chan struct{} // limits concurrent session-revoke goroutines
	waitTimeout           time.Duration // timeout for Wait() during graceful shutdown
	tokenTTL              time.Duration
	cooldownTTL           time.Duration
	maxAttempts           int
	stopCtx               context.Context
	stopCancel            context.CancelFunc
	waitOnce              sync.Once
}

// PasswordResetServiceConfig holds optional configuration for PasswordResetService.
// Zero-valued fields use package defaults.
type PasswordResetServiceConfig struct {
	WaitTimeout          time.Duration        // default: 60s
	TokenTTL             time.Duration        // default: passwordResetTokenTTL
	CooldownTTL          time.Duration        // default: passwordResetCooldownTTL
	MaxAttempts          int                  // default: passwordResetMaxAttempts
	RevokeConcurrency    int                  // default: 10
	LoginRateLimitClearer LoginRateLimitClearer // optional; clears login rate-limit counters after reset
	Auditor               *auditService.Auditor // optional; audit logging for password resets
}

// NewPasswordResetService creates a new password reset service instance
func NewPasswordResetService(
	redis *cache.RedisClient,
	credentialRepo accountRepo.CredentialRepository,
	emailSender PasswordResetEmailSender,
	sessionSvc *sessionService.SessionService,
	tokenRevoker AccountTokenRevoker,
	accountSvc accountService.AccountService,
	db *sql.DB,
	baseURL string,
	logger *zap.Logger,
) *PasswordResetService {
	return NewPasswordResetServiceWithConfig(redis, credentialRepo, emailSender, sessionSvc, tokenRevoker, accountSvc, db, baseURL, logger, PasswordResetServiceConfig{})
}

// NewPasswordResetServiceWithConfig creates a new password reset service instance with the given config.
// Zero-valued config fields use package defaults.
func NewPasswordResetServiceWithConfig(
	redis *cache.RedisClient,
	credentialRepo accountRepo.CredentialRepository,
	emailSender PasswordResetEmailSender,
	sessionSvc *sessionService.SessionService,
	tokenRevoker AccountTokenRevoker,
	accountSvc accountService.AccountService,
	db *sql.DB,
	baseURL string,
	logger *zap.Logger,
	cfg PasswordResetServiceConfig,
) *PasswordResetService {
	logger = utility.EnsureLogger(logger)
	revokeConcurrency := 10
	if cfg.RevokeConcurrency > 0 {
		revokeConcurrency = cfg.RevokeConcurrency
	}
	stopCtx, stopCancel := context.WithCancel(context.Background())
	svc := &PasswordResetService{
		redis:          redis,
		credentialRepo: credentialRepo,
		emailSender:    emailSender,
		sessionSvc:     sessionSvc,
		tokenRevoker:   tokenRevoker,
		accountSvc:     accountSvc,
		db:             db,
		baseURL:        baseURL,
		logger:         logger,
		revokeSem:      make(chan struct{}, revokeConcurrency),
		waitTimeout:    60 * time.Second,
		tokenTTL:       passwordResetTokenTTL,
		cooldownTTL:    passwordResetCooldownTTL,
		maxAttempts:    passwordResetMaxAttempts,
		stopCtx:        stopCtx,
		stopCancel:     stopCancel,
	}
	if cfg.WaitTimeout > 0 {
		svc.waitTimeout = cfg.WaitTimeout
	}
	if cfg.TokenTTL > 0 {
		svc.tokenTTL = cfg.TokenTTL
	}
	if cfg.CooldownTTL > 0 {
		svc.cooldownTTL = cfg.CooldownTTL
	}
	if cfg.MaxAttempts > 0 {
		svc.maxAttempts = cfg.MaxAttempts
	}
	if cfg.LoginRateLimitClearer != nil {
		svc.loginRateLimitClearer = cfg.LoginRateLimitClearer
	} else {
		svc.logger.Warn("LoginRateLimitClearer not configured; login rate limits will not be cleared after password reset")
	}
	if cfg.Auditor != nil {
		svc.auditor = cfg.Auditor
	}
	return svc
}

// RequestReset requests password reset (sends password reset email)
func (s *PasswordResetService) RequestReset(ctx context.Context, email string) error {
	email = strings.ToLower(strings.TrimSpace(email))

	// Check cooldown (fail-closed: if Redis is down, deny the request to prevent email flooding)
	cooldownKey := s.buildCooldownKey(email)
	exists, err := s.redis.Exists(ctx, cooldownKey)
	if err != nil {
		s.logger.Error("Failed to check reset cooldown, denying request", zap.Error(err))
		return ErrServiceUnavailable
	}
	if exists {
		return ErrPasswordCooldown
	}

	// Find email credential
	cred, err := s.credentialRepo.FindByTypeAndIdentifier(ctx, accountDomain.CredentialTypeEmail, email)
	if err != nil {
		// Not found -> Silent success to prevent enumeration.
		// Perform dummy work to mitigate timing side-channel that could reveal
		// whether an email is registered (the real path does token generation +
		// Redis write + SMTP send, which is significantly slower).
		utility.DummyWorkWithContext(ctx)
		s.logger.Debug("Password reset requested for non-existent email", zap.String("email", utility.MaskEmail(email)))
		return nil
	}

	// Check account status
	account, err := s.accountSvc.FindAccountByID(ctx, cred.AccountID)
	if err != nil || account == nil || !account.IsActive() {
		utility.DummyWorkWithContext(ctx)
		s.logger.Debug("Password reset requested for inactive account", zap.String("email", utility.MaskEmail(email)))
		return nil
	}

	// Generate token
	tokenBytes := make([]byte, passwordResetTokenLength)
	if _, err := rand.Read(tokenBytes); err != nil {
		return fmt.Errorf("generate token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	// Store to Redis (using SHA256 hash as the key)
	tokenHash := tokenDomain.HashToken(token)
	data := passwordResetData{
		AccountID: cred.AccountID,
		Email:     email,
		Attempts:  0,
	}
	if account.Username != nil {
		data.Username = *account.Username
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal reset data: %w", err)
	}

	tokenKey := s.buildTokenKey(tokenHash)
	if err := s.redis.Set(ctx, tokenKey, jsonData, s.tokenTTL); err != nil {
		return fmt.Errorf("store reset token: %w", err)
	}

	// Set cooldown BEFORE sending email to prevent rapid-fire email sending.
	// Fail-closed: consistent with the cooldown check above (line 212-214);
	// if Redis is down, deny sending to prevent email flooding.
	if err := s.redis.Set(ctx, cooldownKey, []byte("1"), s.cooldownTTL); err != nil {
		s.logger.Error("Failed to set reset cooldown, denying request", zap.Error(err))
		return ErrServiceUnavailable
	}

	// Send email
	u, err := url.Parse(s.baseURL)
	if err != nil {
		return fmt.Errorf("invalid password reset base URL: %w", err)
	}
	// Use fragment (#) instead of query (?) to prevent token leakage in server logs,
	// HTTP Referer headers, and browser history.
	resetLink := u.String() + "#token=" + url.QueryEscape(token)
	if err := s.emailSender.SendPasswordResetLink(ctx, email, resetLink); err != nil {
		s.logger.Error("Failed to send password reset email", zap.Error(err), zap.String("email", utility.MaskEmail(email)))
		return fmt.Errorf("send reset email: %w", err)
	}

	s.logger.Info("Password reset email sent", zap.String("email", utility.MaskEmail(email)))
	return nil
}

// VerifyAndReset verifies the reset token and sets a new password
func (s *PasswordResetService) VerifyAndReset(ctx context.Context, token, newPassword string) error {
	if err := utility.ValidatePasswordStrength(newPassword); err != nil {
		return err
	}

	// Find token
	tokenHash := tokenDomain.HashToken(token)
	tokenKey := s.buildTokenKey(tokenHash)

	// Atomically check attempts, increment counter, and get data
	result, err := s.redis.RunScript(ctx, checkAndIncrementAttemptsScript, []string{tokenKey},
		s.maxAttempts, int(s.tokenTTL.Seconds())).Result()
	if errors.Is(err, redis.Nil) || result == nil {
		return ErrPasswordResetInvalidToken
	}
	if err != nil {
		return fmt.Errorf("check reset token: %w", err)
	}
	if v, ok := result.(int64); ok && v == -1 {
		return ErrPasswordResetExhausted
	}

	dataStr, ok := result.(string)
	if !ok {
		return fmt.Errorf("unexpected reset token data type")
	}

	var data passwordResetData
	if err := json.Unmarshal([]byte(dataStr), &data); err != nil {
		return fmt.Errorf("unmarshal reset data: %w", err)
	}

	// Verify account is still active before changing password.
	// If the account was suspended or soft-deleted after the reset token was issued,
	// reject the reset to prevent credential modification on inactive accounts.
	account, err := s.accountSvc.FindAccountByID(ctx, data.AccountID)
	if err != nil {
		return fmt.Errorf("find account: %w", err)
	}
	if !account.IsActive() {
		return accountService.ErrAccountNotActive
	}

	// Hash new password
	hashedPassword, err := accountDomain.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	// Find and update password credential in a single transaction to avoid TOCTOU race.
	// The credential could be modified or deleted between the find and update if they
	// use separate connections.
	//
	// Update password first, then delete the reset token.
	// If the process crashes between DB commit and Redis deletion, the password
	// is already changed and the token will expire naturally via TTL — a safe
	// failure mode that avoids locking the user out.
	err = dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		cred, findErr := s.credentialRepo.FindPasswordCredentialTx(ctx, tx, data.AccountID)
		if findErr != nil {
			return fmt.Errorf("find password credential: %w", findErr)
		}
		cred.Value = hashedPassword
		return s.credentialRepo.UpdateCredential(ctx, tx, cred)
	})
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	// One-time use: delete token after successful password update.
	// This runs synchronously but is fast (single Redis DEL).
	if err := s.redis.Del(ctx, tokenKey); err != nil {
		return fmt.Errorf("delete reset token from redis: %w", err)
	}

	// Clear login rate-limit counters so the account is not locked out
	// after a legitimate password reset (e.g., after a brute-force attack
	// triggered rate limiting on the victim's account).
	// Use username (not email) because login rate-limit keys are keyed on username.
	if s.loginRateLimitClearer != nil {
		username := data.Username
		if username == "" {
			// Backward compat: tokens issued before the Username field was added.
			// Fall back to email — may not match if username != email.
			username = data.Email
		}
		if err := s.loginRateLimitClearer.ClearLoginRateLimitsByUsername(ctx, username); err != nil {
			s.logger.Warn("Failed to clear login rate limits after password reset", zap.Error(err))
		}
	}

	// Synchronously revoke all access tokens issued before this password reset.
	// This is a single Redis SET operation and is fast — doing it synchronously
	// closes the window where a stolen access token could still be used.
	if s.tokenRevoker != nil {
		revokeCtx, revokeCancel := context.WithTimeout(ctx, passwordResetSyncRevokeTimeout)
		defer revokeCancel()
		if err := s.tokenRevoker.RevokeAccountTokens(revokeCtx, data.AccountID); err != nil {
			s.logger.Error("Failed to revoke access tokens after password reset",
				zap.String("account_id", utility.MaskOpaqueID(data.AccountID)), zap.Error(err))
		}
	}

	// Asynchronously revoke all old sessions.
	// wg.Add(1) is placed before the select to close the race window between
	// the semaphore send and the goroutine launch. If the default (sync) path
	// is taken, wg.Done() is called immediately to balance the counter.
	s.wg.Add(1)
	select {
	case s.revokeSem <- struct{}{}:
		go func() {
			defer s.wg.Done()
			defer func() { <-s.revokeSem }()
			// Derive from stopCtx so that Wait() can signal shutdown.
			// WithTimeout ensures the goroutine doesn't hang indefinitely
			// even if Redis is unreachable.
			bgCtx, cancel := context.WithTimeout(s.stopCtx, passwordResetRevokeTimeout)
			defer cancel()
			if err := s.sessionSvc.RevokeAllForAccount(bgCtx, data.AccountID); err != nil {
				s.logger.Error("Failed to revoke sessions after password reset",
					zap.String("account_id", utility.MaskOpaqueID(data.AccountID)), zap.Error(err))
			}
		}()
	default:
		s.wg.Done()
		s.logger.Warn("Revoke goroutine limit reached, falling back to synchronous revocation",
			zap.String("account_id", utility.MaskOpaqueID(data.AccountID)),
			zap.Bool("synchronous_fallback", true),
			zap.Int("semaphore_cap", cap(s.revokeSem)))
		syncCtx, syncCancel := context.WithTimeout(context.Background(), passwordResetSyncRevokeTimeout)
		defer syncCancel()
		if err := s.sessionSvc.RevokeAllForAccount(syncCtx, data.AccountID); err != nil {
			s.logger.Error("Failed to revoke sessions synchronously after password reset",
				zap.String("account_id", utility.MaskOpaqueID(data.AccountID)), zap.Error(err))
		}
	}

	s.logger.Info("Password reset successfully", zap.String("account_id", utility.MaskOpaqueID(data.AccountID)))

	// Audit log for password reset (security-sensitive event)
	auditService.AuditLog(ctx, s.auditor, s.logger, auditDomain.NewRecord(
		auditDomain.ActionPasswordReset,
		audit.IPFromContext(ctx),
		&data.AccountID,
		utility.MarshalJSONOrEmpty(map[string]any{"account_id": data.AccountID}),
		utility.MarshalJSONOrEmpty(map[string]any{"ip": audit.IPFromContext(ctx), "user_agent": audit.UserAgentFromContext(ctx)}),
	))

	return nil
}

func (s *PasswordResetService) buildTokenKey(tokenHash string) string {
	return fmt.Sprintf("%s%s", passwordResetTokenKeyPrefix, tokenHash)
}

func (s *PasswordResetService) buildCooldownKey(email string) string {
	return fmt.Sprintf("%s%s", passwordResetCooldownPrefix, strings.ToLower(email))
}

// Wait blocks until all background goroutines (e.g., session revocation) complete.
// Call this during graceful shutdown to ensure in-flight operations finish.
// Returns after the configured timeout even if goroutines are still running, to avoid
// blocking shutdown indefinitely when Redis is unreachable.
// stopCancel() signals background goroutines to wind down — their contexts derive from
// stopCtx, so cancellation propagates. The primary shutdown mechanism
// is the wg.Wait() with the timer fallback below.
func (s *PasswordResetService) Wait() {
	s.stopCancel() // signal background goroutines to wind down via stopCtx cancellation
	s.waitOnce.Do(func() {
		done := make(chan struct{})
		go func() { s.wg.Wait(); close(done) }()
		timer := time.NewTimer(s.waitTimeout)
		defer timer.Stop()
		select {
		case <-done:
		case <-timer.C:
			s.logger.Warn("Timeout waiting for background password reset goroutines",
				zap.Duration("timeout", s.waitTimeout))
		}
	})
}
