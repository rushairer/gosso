package service

import (
	"context"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/captcha/domain"
	"github.com/rushairer/gosso/utility"
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

// verifyCaptchaScript atomically verifies a captcha in Redis.
// KEYS[1] = captcha key
// ARGV[1] = user-provided answer
// Returns: "ok" | "not_found" | "expired" | "already_used" | "mismatch"
var verifyCaptchaScript = redis.NewScript(`
local cjson = require('cjson')
local data = redis.call('GET', KEYS[1])
if not data then
    return "not_found"
end
local c = cjson.decode(data)
local timeArr = redis.call('TIME')
local now = tonumber(timeArr[1])
if c.expires_at_unix and now > c.expires_at_unix then
    redis.call('DEL', KEYS[1])
    return "expired"
end
if c.used then
    return "already_used"
end
if c.answer ~= ARGV[1] then
    return "mismatch"
end
c.used = true
redis.call('SET', KEYS[1], cjson.encode(c), 'KEEPTTL')
return "ok"
`)

// NewCaptchaService creates a new captcha service instance
func NewCaptchaService(redis *cache.RedisClient, logger *zap.Logger) *CaptchaService {
	logger = utility.EnsureLogger(logger)

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

	now := time.Now()
	captcha := &domain.Captcha{
		ID:            uuid.New(),
		Type:          domain.CaptchaTypeMath,
		Answer:        answer,
		CreatedAt:     now,
		ExpiresAt:     now.Add(s.captchaTTL),
		ExpiresAtUnix: now.Add(s.captchaTTL).Unix(),
		Used:          false,
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

	now := time.Now()
	captcha := &domain.Captcha{
		ID:            uuid.New(),
		Type:          domain.CaptchaTypeDigit,
		Answer:        code,
		CreatedAt:     now,
		ExpiresAt:     now.Add(s.captchaTTL),
		ExpiresAtUnix: now.Add(s.captchaTTL).Unix(),
		Used:          false,
	}

	if err := s.storeCaptcha(ctx, captcha); err != nil {
		return nil, "", err
	}

	s.logger.Debug("Digit captcha generated", zap.String("captcha_id", captcha.ID.String()))
	return captcha, code, nil
}

// VerifyCaptcha verifies a captcha atomically using a Redis Lua script.
// This prevents TOCTOU races between concurrent verification attempts.
func (s *CaptchaService) VerifyCaptcha(ctx context.Context, captchaID uuid.UUID, answer string) error {
	key := s.buildCaptchaKey(captchaID)

	result, err := verifyCaptchaScript.Run(ctx, s.redis.GetClient(), []string{key}, answer).Result()
	if err != nil {
		s.logger.Error("Captcha verification script error", zap.Error(err), zap.String("captcha_id", captchaID.String()))
		return fmt.Errorf("verify captcha: %w", err)
	}

	status, ok := result.(string)
	if !ok {
		return fmt.Errorf("unexpected captcha verify result type")
	}

	switch status {
	case "ok":
		if err := s.redis.Del(ctx, key); err != nil {
			s.logger.Warn("Failed to delete captcha after successful verification", zap.String("captcha_id", captchaID.String()), zap.Error(err))
		}
		s.logger.Info("Captcha verified successfully", zap.String("captcha_id", captchaID.String()))
		return nil
	case "not_found":
		return ErrCaptchaNotFound
	case "expired":
		s.logger.Warn("Captcha expired", zap.String("captcha_id", captchaID.String()))
		return ErrCaptchaExpired
	case "already_used":
		s.logger.Warn("Captcha already used", zap.String("captcha_id", captchaID.String()))
		return ErrCaptchaUsed
	case "mismatch":
		s.logger.Warn("Captcha verification failed", zap.String("captcha_id", captchaID.String()))
		return ErrCaptchaInvalid
	default:
		return fmt.Errorf("unknown captcha verify status: %s", status)
	}
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
	ErrCaptchaNotFound = errors.New("captcha not found")
	ErrCaptchaExpired  = errors.New("captcha expired")
	ErrCaptchaUsed     = errors.New("captcha already used")
	ErrCaptchaInvalid  = errors.New("captcha verification failed")
)
