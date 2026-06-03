package service

import (
	"context"
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/captcha/domain"
)

const (
	// CaptchaKeyPrefix is the Redis key prefix for captchas
	CaptchaKeyPrefix = "captcha:"
	// DefaultCaptchaTTL is the default captcha expiration time (5 minutes)
	DefaultCaptchaTTL = 5 * time.Minute
	// CaptchaLength is the length of the captcha code
	CaptchaLength = 6
)

// CaptchaService is the captcha service
type CaptchaService struct {
	redis      *cache.RedisClient
	logger     *zap.Logger
	captchaTTL time.Duration
}

// NewCaptchaService creates a new captcha service instance
func NewCaptchaService(redis *cache.RedisClient, logger *zap.Logger) *CaptchaService {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &CaptchaService{
		redis:      redis,
		logger:     logger,
		captchaTTL: DefaultCaptchaTTL,
	}
}

// SetCaptchaTTL sets the captcha expiration time
func (s *CaptchaService) SetCaptchaTTL(ttl time.Duration) {
	s.captchaTTL = ttl
}

// GenerateMathCaptcha generates a math expression captcha
func (s *CaptchaService) GenerateMathCaptcha(ctx context.Context) (*domain.Captcha, string, error) {
	// Generate a simple addition expression using crypto/rand
	a, err := cryptoRandInt(50)
	if err != nil {
		return nil, "", err
	}
	a++
	b, err := cryptoRandInt(50)
	if err != nil {
		return nil, "", err
	}
	b++
	question := fmt.Sprintf("%d + %d = ?", a, b)
	answer := fmt.Sprintf("%d", a+b)

	captcha := &domain.Captcha{
		ID:        uuid.New(),
		Type:      domain.CaptchaTypeMath,
		Answer:    answer,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(s.captchaTTL),
		Used:      false,
	}

	if err := s.storeCaptcha(ctx, captcha); err != nil {
		return nil, "", err
	}

	s.logger.Debug("Math captcha generated", zap.String("captcha_id", captcha.ID.String()))
	return captcha, question, nil
}

// GenerateDigitCaptcha generates a numeric captcha
func (s *CaptchaService) GenerateDigitCaptcha(ctx context.Context) (*domain.Captcha, string, error) {
	// Generate a 6-digit random number using crypto/rand
	r, err := cryptoRandInt(1000000)
	if err != nil {
		return nil, "", err
	}
	code := fmt.Sprintf("%06d", r)

	captcha := &domain.Captcha{
		ID:        uuid.New(),
		Type:      domain.CaptchaTypeDigit,
		Answer:    code,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(s.captchaTTL),
		Used:      false,
	}

	if err := s.storeCaptcha(ctx, captcha); err != nil {
		return nil, "", err
	}

	s.logger.Debug("Digit captcha generated", zap.String("captcha_id", captcha.ID.String()))
	return captcha, code, nil
}

// VerifyCaptcha verifies a captcha
func (s *CaptchaService) VerifyCaptcha(ctx context.Context, captchaID uuid.UUID, answer string) error {
	captcha, err := s.getCaptcha(ctx, captchaID)
	if err != nil {
		return err
	}

	// Check if expired
	if captcha.IsExpired() {
		s.logger.Warn("Captcha expired", zap.String("captcha_id", captchaID.String()))
		// Delete expired captcha
		_ = s.DeleteCaptcha(ctx, captchaID)
		return ErrCaptchaExpired
	}

	// Check if already used (replay prevention)
	if captcha.Used {
		s.logger.Warn("Captcha already used", zap.String("captcha_id", captchaID.String()))
		return ErrCaptchaUsed
	}

	// Verify answer
	if captcha.Answer != answer {
		s.logger.Warn("Captcha verification failed",
			zap.String("captcha_id", captchaID.String()),
			zap.String("expected", captcha.Answer),
			zap.String("got", answer))
		return ErrCaptchaInvalid
	}

	// Mark as used
	captcha.MarkUsed()
	if err := s.storeCaptcha(ctx, captcha); err != nil {
		s.logger.Error("Failed to mark captcha as used", zap.Error(err))
		// Do not return error, allow verification to pass
	}

	// Optional: delete captcha immediately (more secure)
	_ = s.DeleteCaptcha(ctx, captchaID)

	s.logger.Info("Captcha verified successfully", zap.String("captcha_id", captchaID.String()))
	return nil
}

// DeleteCaptcha deletes a captcha
func (s *CaptchaService) DeleteCaptcha(ctx context.Context, captchaID uuid.UUID) error {
	key := s.buildCaptchaKey(captchaID)
	if err := s.redis.Del(ctx, key); err != nil {
		s.logger.Error("Failed to delete captcha", zap.Error(err), zap.String("captcha_id", captchaID.String()))
		return fmt.Errorf("delete captcha: %w", err)
	}
	return nil
}

// storeCaptcha stores a captcha in Redis
func (s *CaptchaService) storeCaptcha(ctx context.Context, captcha *domain.Captcha) error {
	data, err := json.Marshal(captcha)
	if err != nil {
		s.logger.Error("Failed to marshal captcha", zap.Error(err), zap.String("captcha_id", captcha.ID.String()))
		return fmt.Errorf("marshal captcha: %w", err)
	}

	key := s.buildCaptchaKey(captcha.ID)
	if err := s.redis.Set(ctx, key, data, s.captchaTTL); err != nil {
		s.logger.Error("Failed to store captcha", zap.Error(err), zap.String("captcha_id", captcha.ID.String()))
		return fmt.Errorf("store captcha: %w", err)
	}

	return nil
}

// getCaptcha gets a captcha from Redis
func (s *CaptchaService) getCaptcha(ctx context.Context, captchaID uuid.UUID) (*domain.Captcha, error) {
	key := s.buildCaptchaKey(captchaID)
	data, err := s.redis.Get(ctx, key)
	if err == cache.ErrKeyNotFound {
		return nil, ErrCaptchaNotFound
	}
	if err != nil {
		s.logger.Error("Failed to get captcha", zap.Error(err), zap.String("captcha_id", captchaID.String()))
		return nil, fmt.Errorf("get captcha: %w", err)
	}

	var captcha domain.Captcha
	if err := json.Unmarshal([]byte(data), &captcha); err != nil {
		s.logger.Error("Failed to unmarshal captcha", zap.Error(err), zap.String("captcha_id", captchaID.String()))
		return nil, fmt.Errorf("unmarshal captcha: %w", err)
	}

	return &captcha, nil
}

// buildCaptchaKey builds a Redis key
func (s *CaptchaService) buildCaptchaKey(captchaID uuid.UUID) string {
	return fmt.Sprintf("%s%s", CaptchaKeyPrefix, captchaID.String())
}

// cryptoRandInt returns a cryptographically secure random int in [0, max).
func cryptoRandInt(max int64) (int64, error) {
	n, err := crand.Int(crand.Reader, big.NewInt(max))
	if err != nil {
		return 0, fmt.Errorf("crypto/rand failed: %w", err)
	}
	return n.Int64(), nil
}

// Error definitions
var (
	ErrCaptchaNotFound = fmt.Errorf("captcha not found")
	ErrCaptchaExpired  = fmt.Errorf("captcha expired")
	ErrCaptchaUsed     = fmt.Errorf("captcha already used")
	ErrCaptchaInvalid  = fmt.Errorf("captcha verification failed")
)
