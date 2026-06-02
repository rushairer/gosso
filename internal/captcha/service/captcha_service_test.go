package service

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/captcha/domain"
)

func setupTestCaptchaService(t *testing.T) *CaptchaService {
	logger := zap.NewNop()
	dsn := "redis://localhost:6379/15"

	redisClient, err := cache.NewRedisClient(dsn, 10, 5*time.Second, logger)
	if err != nil {
		t.Skip("Redis not available, skipping test:", err)
	}

	service := NewCaptchaService(redisClient, logger)
	service.SetCaptchaTTL(10 * time.Second) // 测试用短过期时间

	return service
}

func TestCaptchaService_GenerateMathCaptcha(t *testing.T) {
	service := setupTestCaptchaService(t)
	defer service.redis.Close()

	ctx := context.Background()

	// 生成验证码
	captcha, question, err := service.GenerateMathCaptcha(ctx)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, captcha.ID)
	assert.NotEmpty(t, question)
	assert.Equal(t, domain.CaptchaTypeMath, captcha.Type)
	assert.NotEmpty(t, captcha.Answer)

	t.Logf("Math captcha: %s, answer: %s", question, captcha.Answer)

	// 清理
	_ = service.DeleteCaptcha(ctx, captcha.ID)
}

func TestCaptchaService_GenerateDigitCaptcha(t *testing.T) {
	service := setupTestCaptchaService(t)
	defer service.redis.Close()

	ctx := context.Background()

	// 生成验证码
	captcha, code, err := service.GenerateDigitCaptcha(ctx)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, captcha.ID)
	assert.Equal(t, 6, len(code))
	assert.Equal(t, domain.CaptchaTypeDigit, captcha.Type)
	assert.Equal(t, code, captcha.Answer)

	t.Logf("Digit captcha: %s", code)

	// 清理
	_ = service.DeleteCaptcha(ctx, captcha.ID)
}

func TestCaptchaService_VerifyCaptcha_Success(t *testing.T) {
	service := setupTestCaptchaService(t)
	defer service.redis.Close()

	ctx := context.Background()

	// 生成验证码
	captcha, code, err := service.GenerateDigitCaptcha(ctx)
	require.NoError(t, err)

	// 验证验证码（正确答案）
	err = service.VerifyCaptcha(ctx, captcha.ID, code)
	assert.NoError(t, err)

	// 验证后应该被删除
	err = service.VerifyCaptcha(ctx, captcha.ID, code)
	assert.Equal(t, ErrCaptchaNotFound, err)
}

func TestCaptchaService_VerifyCaptcha_WrongAnswer(t *testing.T) {
	service := setupTestCaptchaService(t)
	defer service.redis.Close()

	ctx := context.Background()

	// 生成验证码
	captcha, _, err := service.GenerateDigitCaptcha(ctx)
	require.NoError(t, err)

	// 验证验证码（错误答案）
	err = service.VerifyCaptcha(ctx, captcha.ID, "000000")
	assert.Equal(t, ErrCaptchaInvalid, err)

	// 清理
	_ = service.DeleteCaptcha(ctx, captcha.ID)
}

func TestCaptchaService_VerifyCaptcha_NotFound(t *testing.T) {
	service := setupTestCaptchaService(t)
	defer service.redis.Close()

	ctx := context.Background()

	// 验证不存在的验证码
	err := service.VerifyCaptcha(ctx, uuid.New(), "123456")
	assert.Equal(t, ErrCaptchaNotFound, err)
}

func TestCaptchaService_VerifyCaptcha_Expired(t *testing.T) {
	service := setupTestCaptchaService(t)
	defer service.redis.Close()

	ctx := context.Background()

	// 设置极短的过期时间
	service.SetCaptchaTTL(1 * time.Second)

	// 生成验证码
	captcha, code, err := service.GenerateDigitCaptcha(ctx)
	require.NoError(t, err)

	// 等待过期
	time.Sleep(2 * time.Second)

	// 验证过期的验证码
	err = service.VerifyCaptcha(ctx, captcha.ID, code)
	assert.Equal(t, ErrCaptchaNotFound, err) // Redis 会自动删除过期的键
}
