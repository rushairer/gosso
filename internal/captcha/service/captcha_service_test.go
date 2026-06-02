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
	service.SetCaptchaTTL(10 * time.Second) // Short expiration time for testing

	return service
}

func TestCaptchaService_GenerateMathCaptcha(t *testing.T) {
	service := setupTestCaptchaService(t)
	defer service.redis.Close()

	ctx := context.Background()

	// Generate captcha
	captcha, question, err := service.GenerateMathCaptcha(ctx)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, captcha.ID)
	assert.NotEmpty(t, question)
	assert.Equal(t, domain.CaptchaTypeMath, captcha.Type)
	assert.NotEmpty(t, captcha.Answer)

	t.Logf("Math captcha: %s, answer: %s", question, captcha.Answer)

	// Cleanup
	_ = service.DeleteCaptcha(ctx, captcha.ID)
}

func TestCaptchaService_GenerateDigitCaptcha(t *testing.T) {
	service := setupTestCaptchaService(t)
	defer service.redis.Close()

	ctx := context.Background()

	// Generate captcha
	captcha, code, err := service.GenerateDigitCaptcha(ctx)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, captcha.ID)
	assert.Equal(t, 6, len(code))
	assert.Equal(t, domain.CaptchaTypeDigit, captcha.Type)
	assert.Equal(t, code, captcha.Answer)

	t.Logf("Digit captcha: %s", code)

	// Cleanup
	_ = service.DeleteCaptcha(ctx, captcha.ID)
}

func TestCaptchaService_VerifyCaptcha_Success(t *testing.T) {
	service := setupTestCaptchaService(t)
	defer service.redis.Close()

	ctx := context.Background()

	// Generate captcha
	captcha, code, err := service.GenerateDigitCaptcha(ctx)
	require.NoError(t, err)

	// Verify captcha (correct answer)
	err = service.VerifyCaptcha(ctx, captcha.ID, code)
	assert.NoError(t, err)

	// Should be deleted after verification
	err = service.VerifyCaptcha(ctx, captcha.ID, code)
	assert.Equal(t, ErrCaptchaNotFound, err)
}

func TestCaptchaService_VerifyCaptcha_WrongAnswer(t *testing.T) {
	service := setupTestCaptchaService(t)
	defer service.redis.Close()

	ctx := context.Background()

	// Generate captcha
	captcha, _, err := service.GenerateDigitCaptcha(ctx)
	require.NoError(t, err)

	// Verify captcha (wrong answer)
	err = service.VerifyCaptcha(ctx, captcha.ID, "000000")
	assert.Equal(t, ErrCaptchaInvalid, err)

	// Cleanup
	_ = service.DeleteCaptcha(ctx, captcha.ID)
}

func TestCaptchaService_VerifyCaptcha_NotFound(t *testing.T) {
	service := setupTestCaptchaService(t)
	defer service.redis.Close()

	ctx := context.Background()

	// Verify a non-existent captcha
	err := service.VerifyCaptcha(ctx, uuid.New(), "123456")
	assert.Equal(t, ErrCaptchaNotFound, err)
}

func TestCaptchaService_VerifyCaptcha_Expired(t *testing.T) {
	service := setupTestCaptchaService(t)
	defer service.redis.Close()

	ctx := context.Background()

	// Set a very short expiration time
	service.SetCaptchaTTL(1 * time.Second)

	// Generate captcha
	captcha, code, err := service.GenerateDigitCaptcha(ctx)
	require.NoError(t, err)

	// Wait for expiration
	time.Sleep(2 * time.Second)

	// Verify expired captcha
	err = service.VerifyCaptcha(ctx, captcha.ID, code)
	assert.Equal(t, ErrCaptchaNotFound, err) // Redis automatically deletes expired keys
}
