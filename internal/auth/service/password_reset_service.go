package service

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/account/domain"
	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	accountService "github.com/rushairer/gosso/internal/account/service"
	"github.com/rushairer/gosso/internal/cache"
	sessionService "github.com/rushairer/gosso/internal/session/service"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
)

const (
	PasswordResetTokenKeyPrefix = "password_reset:token:"
	PasswordResetCooldownPrefix = "password_reset:cooldown:"
	PasswordResetTokenLength    = 32
	PasswordResetTokenTTL       = 30 * time.Minute
	PasswordResetCooldownTTL    = 60 * time.Second
	PasswordResetMaxAttempts    = 5
)

// PasswordResetEmailSender password reset email sender interface
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
	}
}

// RequestReset requests password reset (sends password reset email)
func (s *PasswordResetService) RequestReset(ctx context.Context, email string) error {
	// Check cooldown
	cooldownKey := s.buildCooldownKey(email)
	exists, err := s.redis.Exists(ctx, cooldownKey)
	if err != nil {
		s.logger.Warn("Failed to check reset cooldown", zap.Error(err))
	}
	if exists {
		return errors.New("please wait before requesting another reset")
	}

	// Find email credential
	cred, err := s.credentialRepo.FindByTypeAndIdentifier(ctx, domain.CredentialTypeEmail, email)
	if err != nil {
		// Not found -> Silent success to prevent enumeration
		s.logger.Debug("Password reset requested for non-existent email", zap.String("email", email))
		return nil
	}

	// Check account status
	account, err := s.accountSvc.FindAccountByID(ctx, cred.AccountID)
	if err != nil || !account.IsActive() {
		s.logger.Debug("Password reset requested for inactive account", zap.String("email", email))
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

	// Set cooldown
	if err := s.redis.Set(ctx, cooldownKey, []byte("1"), PasswordResetCooldownTTL); err != nil {
		s.logger.Warn("Failed to set reset cooldown", zap.Error(err))
	}

	// Send email
	resetLink := fmt.Sprintf("%s?token=%s", s.baseURL, token)
	if err := s.emailSender.SendPasswordResetLink(ctx, email, resetLink); err != nil {
		s.logger.Error("Failed to send password reset email", zap.Error(err), zap.String("email", email))
		return fmt.Errorf("send reset email: %w", err)
	}

	s.logger.Info("Password reset email sent", zap.String("email", email))
	return nil
}

// VerifyAndReset verifies the reset token and sets a new password
func (s *PasswordResetService) VerifyAndReset(ctx context.Context, token, newPassword string) error {
	if len(newPassword) < 8 {
		return errors.New("password must be at least 8 characters")
	}

	// Find token
	tokenHash := tokenDomain.HashToken(token)
	tokenKey := s.buildTokenKey(tokenHash)

	raw, err := s.redis.Get(ctx, tokenKey)
	if err == cache.ErrKeyNotFound {
		return errors.New("invalid or expired reset token")
	}
	if err != nil {
		return fmt.Errorf("get reset token: %w", err)
	}

	var data passwordResetData
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return fmt.Errorf("unmarshal reset data: %w", err)
	}

	// Check attempts count
	if data.Attempts >= PasswordResetMaxAttempts {
		_ = s.redis.Del(ctx, tokenKey)
		return errors.New("reset token exhausted, please request a new one")
	}

	// One-time use: delete immediately
	_ = s.redis.Del(ctx, tokenKey)

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

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	cred.Value = hashedPassword
	if err := s.credentialRepo.UpdateCredential(ctx, tx, cred); err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	// Asynchronously revoke all old sessions
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.sessionSvc.RevokeAllForAccount(bgCtx, data.AccountID); err != nil {
			s.logger.Error("Failed to revoke sessions after password reset",
				zap.String("account_id", data.AccountID), zap.Error(err))
		}
	}()

	s.logger.Info("Password reset successfully", zap.String("account_id", data.AccountID))
	return nil
}

func (s *PasswordResetService) buildTokenKey(tokenHash string) string {
	return fmt.Sprintf("%s%s", PasswordResetTokenKeyPrefix, tokenHash)
}

func (s *PasswordResetService) buildCooldownKey(email string) string {
	return fmt.Sprintf("%s%s", PasswordResetCooldownPrefix, email)
}
