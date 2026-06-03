package service

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/rushairer/gosso/utility"
)

const (
	PasswordResetTokenKeyPrefix = "password_reset:token:"
	PasswordResetCooldownPrefix = "password_reset:cooldown:"
	PasswordResetTokenLength    = 32
	PasswordResetTokenTTL       = 30 * time.Minute
	PasswordResetCooldownTTL    = 60 * time.Second
	PasswordResetMaxAttempts    = 5
	PasswordResetRevokeTimeout  = 30 * time.Second
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
	if logger == nil {
		logger = zap.NewNop()
	}
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
	if err := s.redis.Set(ctx, tokenKey, jsonData, PasswordResetTokenTTL); err != nil {
		return fmt.Errorf("store reset token: %w", err)
	}

	// Set cooldown (fail-open: if Redis is down, we lose cooldown but can still reset)
	if err := s.redis.Set(ctx, cooldownKey, []byte("1"), PasswordResetCooldownTTL); err != nil {
		s.logger.Warn("Failed to set reset cooldown", zap.Error(err))
	}

	// Send email
	resetLink := fmt.Sprintf("%s?token=%s", s.baseURL, token)
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
	result, err := checkAndIncrementAttemptsScript.Run(ctx, s.redis.GetClient(), []string{tokenKey},
		PasswordResetMaxAttempts, int(PasswordResetTokenTTL.Seconds())).Result()
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
	err = dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.credentialRepo.UpdateCredential(ctx, tx, cred)
	})
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	// One-time use: delete token only after successful password update
	if err := s.redis.Del(ctx, tokenKey); err != nil {
		s.logger.Warn("Failed to delete reset token from Redis, token may be reusable until TTL",
			zap.Error(err), zap.String("token_hash", tokenHash))
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
		s.logger.Warn("Revoke goroutine limit reached, skipping async session revocation",
			zap.String("account_id", data.AccountID))
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
func (s *PasswordResetService) Wait() {
	s.wg.Wait()
}
