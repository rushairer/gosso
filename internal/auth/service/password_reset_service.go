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
	"github.com/rushairer/gosso/internal/cache"
	dbutil "github.com/rushairer/gosso/internal/db"
	sessionService "github.com/rushairer/gosso/internal/session/service"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	"github.com/rushairer/gosso/internal/utility"
)

const (
	PasswordResetTokenKeyPrefix    = "password_reset:token:"
	PasswordResetCooldownPrefix    = "password_reset:cooldown:"
	PasswordResetTokenLength       = 32
	PasswordResetTokenTTL          = 30 * time.Minute
	PasswordResetCooldownTTL       = 60 * time.Second
	PasswordResetMaxAttempts       = 5
	PasswordResetRevokeTimeout     = 30 * time.Second
	PasswordResetSyncRevokeTimeout = 5 * time.Second
)

// checkAndIncrementAttemptsScript atomically checks attempt count, increments, and returns the data.
// Returns: data string on success, -1 if exhausted (key deleted), nil if key not found.
var checkAndIncrementAttemptsScript = redis.NewScript(`
local data = redis.call('GET', KEYS[1])
if not data then
    return nil
end
local cjson = require('cjson')
local obj = cjson.decode(data)
local max_attempts = tonumber(ARGV[1])
if obj.attempts >= max_attempts then
    return -1
end
obj.attempts = obj.attempts + 1
local updated = cjson.encode(obj)
redis.call('SETEX', KEYS[1], ARGV[2], updated)
return updated
`)

// PasswordResetEmailSender abstracts email delivery for password-reset links.
// Implementations must not leak whether the address is registered.
type PasswordResetEmailSender interface {
	SendPasswordResetLink(ctx context.Context, to, resetLink string) error
}

type passwordResetData struct {
	AccountID string `json:"account_id"`
	Email     string `json:"email"`
	Attempts  int    `json:"attempts"`
}

// PasswordResetService password reset service
type PasswordResetService struct {
	redis          *cache.RedisClient
	credentialRepo accountRepo.CredentialRepository
	emailSender    PasswordResetEmailSender
	sessionSvc     *sessionService.SessionService
	accountSvc     accountService.AccountService
	db             *sql.DB
	baseURL        string
	logger         *zap.Logger
	wg             sync.WaitGroup
	revokeSem      chan struct{} // limits concurrent session-revoke goroutines
	waitTimeout    time.Duration // timeout for Wait() during graceful shutdown
	tokenTTL       time.Duration
	cooldownTTL    time.Duration
	maxAttempts    int
}

// NewPasswordResetService creates a new password reset service instance
func NewPasswordResetService(
	redis *cache.RedisClient,
	credentialRepo accountRepo.CredentialRepository,
	emailSender PasswordResetEmailSender,
	sessionSvc *sessionService.SessionService,
	accountSvc accountService.AccountService,
	db *sql.DB,
	baseURL string,
	logger *zap.Logger,
) *PasswordResetService {
	logger = utility.EnsureLogger(logger)
	return &PasswordResetService{
		redis:          redis,
		credentialRepo: credentialRepo,
		emailSender:    emailSender,
		sessionSvc:     sessionSvc,
		accountSvc:     accountSvc,
		db:             db,
		baseURL:        baseURL,
		logger:         logger,
		revokeSem:      make(chan struct{}, 10),
		waitTimeout:    60 * time.Second,
		tokenTTL:       PasswordResetTokenTTL,
		cooldownTTL:    PasswordResetCooldownTTL,
		maxAttempts:    PasswordResetMaxAttempts,
	}
}

// SetWaitTimeout overrides the default timeout for Wait() during graceful shutdown.
func (s *PasswordResetService) SetWaitTimeout(d time.Duration) {
	if d > 0 {
		s.waitTimeout = d
	}
}

// SetTokenTTL overrides the default password reset token TTL.
func (s *PasswordResetService) SetTokenTTL(d time.Duration) {
	if d > 0 {
		s.tokenTTL = d
	}
}

// SetCooldownTTL overrides the default password reset cooldown TTL.
func (s *PasswordResetService) SetCooldownTTL(d time.Duration) {
	if d > 0 {
		s.cooldownTTL = d
	}
}

// SetMaxAttempts overrides the default password reset max attempts.
func (s *PasswordResetService) SetMaxAttempts(n int) {
	if n > 0 {
		s.maxAttempts = n
	}
}

// RequestReset requests password reset (sends password reset email)
func (s *PasswordResetService) RequestReset(ctx context.Context, email string) error {
	email = strings.ToLower(strings.TrimSpace(email))

	// Check cooldown (fail-open: if Redis is down, we still allow the request)
	cooldownKey := s.buildCooldownKey(email)
	exists, err := s.redis.Exists(ctx, cooldownKey)
	if err != nil {
		s.logger.Warn("Failed to check reset cooldown, proceeding anyway", zap.Error(err))
	}
	if exists {
		return errors.New("please wait before requesting another reset")
	}

	// Find email credential
	cred, err := s.credentialRepo.FindByTypeAndIdentifier(ctx, accountDomain.CredentialTypeEmail, email)
	if err != nil {
		// Not found -> Silent success to prevent enumeration
		s.logger.Debug("Password reset requested for non-existent email", zap.String("email", utility.MaskEmail(email)))
		return nil
	}

	// Check account status
	account, err := s.accountSvc.FindAccountByID(ctx, cred.AccountID)
	if err != nil || !account.IsActive() {
		s.logger.Debug("Password reset requested for inactive account", zap.String("email", utility.MaskEmail(email)))
		return nil
	}

	// Generate token
	tokenBytes := make([]byte, PasswordResetTokenLength)
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
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal reset data: %w", err)
	}

	tokenKey := s.buildTokenKey(tokenHash)
	if err := s.redis.Set(ctx, tokenKey, jsonData, s.tokenTTL); err != nil {
		return fmt.Errorf("store reset token: %w", err)
	}

	// Set cooldown (fail-open: if Redis is down, we lose cooldown but can still reset)
	if err := s.redis.Set(ctx, cooldownKey, []byte("1"), s.cooldownTTL); err != nil {
		s.logger.Warn("Failed to set reset cooldown", zap.Error(err))
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
	if err == redis.Nil || result == nil {
		return errors.New("invalid or expired reset token")
	}
	if err != nil {
		return fmt.Errorf("check reset token: %w", err)
	}
	if result == int64(-1) {
		return errors.New("reset token exhausted, please request a new one")
	}

	dataStr, ok := result.(string)
	if !ok {
		return fmt.Errorf("unexpected reset token data type")
	}

	var data passwordResetData
	if err := json.Unmarshal([]byte(dataStr), &data); err != nil {
		return fmt.Errorf("unmarshal reset data: %w", err)
	}

	// Hash new password
	hashedPassword, err := accountDomain.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	// Find password credential and update it
	cred, err := s.credentialRepo.FindPasswordCredential(ctx, data.AccountID)
	if err != nil {
		return fmt.Errorf("find password credential: %w", err)
	}

	cred.Value = hashedPassword

	// Update password first, then delete the reset token.
	// If the process crashes between DB commit and Redis deletion, the password
	// is already changed and the token will expire naturally via TTL — a safe
	// failure mode that avoids locking the user out.
	err = dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.credentialRepo.UpdateCredential(ctx, tx, cred)
	})
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	// One-time use: delete token after successful password update.
	if err := s.redis.Del(ctx, tokenKey); err != nil {
		// Retry once immediately without blocking the HTTP handler.
		// If the retry also fails, the token will expire naturally via TTL.
		if retryErr := s.redis.Del(ctx, tokenKey); retryErr != nil {
			s.logger.Warn("Failed to delete reset token from Redis after retry, token will expire via TTL",
				zap.Error(retryErr), zap.String("token_hash", tokenHash))
		}
	}

	// Asynchronously revoke all old sessions
	select {
	case s.revokeSem <- struct{}{}:
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.revokeSem }()
			bgCtx, cancel := context.WithTimeout(context.Background(), PasswordResetRevokeTimeout)
			defer cancel()
			if err := s.sessionSvc.RevokeAllForAccount(bgCtx, data.AccountID); err != nil {
				s.logger.Error("Failed to revoke sessions after password reset",
					zap.String("account_id", data.AccountID), zap.Error(err))
			}
		}()
	default:
		s.logger.Warn("Revoke goroutine limit reached, falling back to synchronous revocation",
			zap.String("account_id", data.AccountID))
		syncCtx, syncCancel := context.WithTimeout(context.Background(), PasswordResetSyncRevokeTimeout)
		defer syncCancel()
		if err := s.sessionSvc.RevokeAllForAccount(syncCtx, data.AccountID); err != nil {
			s.logger.Error("Failed to revoke sessions synchronously after password reset",
				zap.String("account_id", data.AccountID), zap.Error(err))
		}
	}

	s.logger.Info("Password reset successfully", zap.String("account_id", data.AccountID))
	return nil
}

func (s *PasswordResetService) buildTokenKey(tokenHash string) string {
	return fmt.Sprintf("%s%s", PasswordResetTokenKeyPrefix, tokenHash)
}

func (s *PasswordResetService) buildCooldownKey(email string) string {
	return fmt.Sprintf("%s%s", PasswordResetCooldownPrefix, strings.ToLower(email))
}

// Wait blocks until all background goroutines (e.g., session revocation) complete.
// Call this during graceful shutdown to ensure in-flight operations finish.
// Returns after the configured timeout even if goroutines are still running, to avoid
// blocking shutdown indefinitely when Redis is unreachable.
func (s *PasswordResetService) Wait() {
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(s.waitTimeout):
		s.logger.Warn("Timeout waiting for background password reset goroutines",
			zap.Duration("timeout", s.waitTimeout))
	}
}
