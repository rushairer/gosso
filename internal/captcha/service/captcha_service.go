package service

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"github.com/google/uuid"
	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/captcha/domain"
	"go.uber.org/zap"
)

const (
	// CaptchaKeyPrefix Redis 验证码键前缀
	CaptchaKeyPrefix = "captcha:"
	// DefaultCaptchaTTL 默认验证码过期时间（5分钟）
	DefaultCaptchaTTL = 5 * time.Minute
	// CaptchaLength 验证码长度
	CaptchaLength = 6
)

// CaptchaService 验证码服务
type CaptchaService struct {
	redis      *cache.RedisClient
	logger     *zap.Logger
	captchaTTL time.Duration
}

// NewCaptchaService 创建验证码服务实例
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

// SetCaptchaTTL 设置验证码过期时间
func (s *CaptchaService) SetCaptchaTTL(ttl time.Duration) {
	s.captchaTTL = ttl
}

// GenerateMathCaptcha 生成数学算式验证码
func (s *CaptchaService) GenerateMathCaptcha(ctx context.Context) (*domain.Captcha, string, error) {
	// 生成简单的加法算式
	a := rand.Intn(50) + 1
	b := rand.Intn(50) + 1
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

// GenerateDigitCaptcha 生成数字验证码
func (s *CaptchaService) GenerateDigitCaptcha(ctx context.Context) (*domain.Captcha, string, error) {
	// 生成6位随机数字
	code := fmt.Sprintf("%06d", rand.Intn(1000000))

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

// VerifyCaptcha 验证验证码
func (s *CaptchaService) VerifyCaptcha(ctx context.Context, captchaID uuid.UUID, answer string) error {
	captcha, err := s.getCaptcha(ctx, captchaID)
	if err != nil {
		return err
	}

	// 检查是否已过期
	if captcha.IsExpired() {
		s.logger.Warn("Captcha expired", zap.String("captcha_id", captchaID.String()))
		// 删除过期验证码
		_ = s.DeleteCaptcha(ctx, captchaID)
		return ErrCaptchaExpired
	}

	// 检查是否已使用（防重放）
	if captcha.Used {
		s.logger.Warn("Captcha already used", zap.String("captcha_id", captchaID.String()))
		return ErrCaptchaUsed
	}

	// 验证答案
	if captcha.Answer != answer {
		s.logger.Warn("Captcha verification failed",
			zap.String("captcha_id", captchaID.String()),
			zap.String("expected", captcha.Answer),
			zap.String("got", answer))
		return ErrCaptchaInvalid
	}

	// 标记为已使用
	captcha.MarkUsed()
	if err := s.storeCaptcha(ctx, captcha); err != nil {
		s.logger.Error("Failed to mark captcha as used", zap.Error(err))
		// 不返回错误，允许验证通过
	}

	// 可选：立即删除验证码（更安全）
	_ = s.DeleteCaptcha(ctx, captchaID)

	s.logger.Info("Captcha verified successfully", zap.String("captcha_id", captchaID.String()))
	return nil
}

// DeleteCaptcha 删除验证码
func (s *CaptchaService) DeleteCaptcha(ctx context.Context, captchaID uuid.UUID) error {
	key := s.buildCaptchaKey(captchaID)
	if err := s.redis.Del(ctx, key); err != nil {
		s.logger.Error("Failed to delete captcha", zap.Error(err), zap.String("captcha_id", captchaID.String()))
		return fmt.Errorf("delete captcha: %w", err)
	}
	return nil
}

// storeCaptcha 存储验证码到 Redis
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

// getCaptcha 从 Redis 获取验证码
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

// buildCaptchaKey 构建 Redis 键
func (s *CaptchaService) buildCaptchaKey(captchaID uuid.UUID) string {
	return fmt.Sprintf("%s%s", CaptchaKeyPrefix, captchaID.String())
}

// 错误定义
var (
	ErrCaptchaNotFound = fmt.Errorf("captcha not found")
	ErrCaptchaExpired  = fmt.Errorf("captcha expired")
	ErrCaptchaUsed     = fmt.Errorf("captcha already used")
	ErrCaptchaInvalid  = fmt.Errorf("captcha verification failed")
)
