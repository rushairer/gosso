package service

import (
	"context"
	"testing"
	"time"

	"github.com/rushairer/gosso/internal/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// stubEmailService captures the code instead of sending email
type stubEmailService struct {
	sentCodes []string
}

func (s *stubEmailService) SendVerificationCode(_ context.Context, _, code string) error {
	s.sentCodes = append(s.sentCodes, code)
	return nil
}

// stubSMSService is a no-op SMS service for testing
type stubSMSService struct{}

func (s *stubSMSService) SendVerificationCode(_ context.Context, _, _ string) error {
	return nil
}

func setupTestVerificationService(t *testing.T) (*VerificationService, *cache.RedisClient, *stubEmailService) {
	t.Helper()
	logger := zap.NewNop()
	dsn := "redis://localhost:6379/15"

	redisClient, err := cache.NewRedisClient(dsn, 10, 5*time.Second, logger)
	if err != nil {
		t.Skip("Redis not available, skipping test:", err)
	}

	emailSvc := &stubEmailService{}
	smsSvc := &stubSMSService{}
	svc := NewVerificationService(redisClient, emailSvc, smsSvc, logger)

	return svc, redisClient, emailSvc
}

func TestVerifyCode_Success(t *testing.T) {
	svc, redis, emailSvc := setupTestVerificationService(t)
	defer redis.Close()

	ctx := context.Background()

	// 发送验证码
	err := svc.SendCode(ctx, "email", "test@example.com", "account-001")
	require.NoError(t, err)
	require.Len(t, emailSvc.sentCodes, 1)
	code := emailSvc.sentCodes[0]

	// 验证
	accountID, err := svc.VerifyCode(ctx, "email", "test@example.com", code)
	require.NoError(t, err)
	assert.Equal(t, "account-001", accountID)
}

func TestVerifyCode_Wrong(t *testing.T) {
	svc, redis, _ := setupTestVerificationService(t)
	defer redis.Close()

	ctx := context.Background()

	// 发送验证码
	err := svc.SendCode(ctx, "email", "wrong@example.com", "account-002")
	require.NoError(t, err)

	// 错误验证码
	_, err = svc.VerifyCode(ctx, "email", "wrong@example.com", "000000")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid verification code")
}

func TestVerifyCode_Exhausted(t *testing.T) {
	svc, redis, _ := setupTestVerificationService(t)
	defer redis.Close()

	ctx := context.Background()

	// 发送验证码
	err := svc.SendCode(ctx, "email", "exhaust@example.com", "account-003")
	require.NoError(t, err)

	// 5 次错误尝试
	for i := 0; i < 5; i++ {
		_, _ = svc.VerifyCode(ctx, "email", "exhaust@example.com", "wrong")
	}

	// 第 6 次应返回 exhausted
	_, err = svc.VerifyCode(ctx, "email", "exhaust@example.com", "wrong")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exhausted")
}

func TestVerifyCode_Expired(t *testing.T) {
	svc, redis, emailSvc := setupTestVerificationService(t)
	defer redis.Close()

	ctx := context.Background()

	// 发送验证码
	err := svc.SendCode(ctx, "email", "expired@example.com", "account-004")
	require.NoError(t, err)

	// 手动删除 key 模拟过期
	codeKey := svc.buildCodeKey("email", "expired@example.com")
	_ = redis.Del(ctx, codeKey)

	// 验证
	_, err = svc.VerifyCode(ctx, "email", "expired@example.com", emailSvc.sentCodes[0])
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired or not found")
}

func TestSendCode_Cooldown(t *testing.T) {
	svc, redis, _ := setupTestVerificationService(t)
	defer redis.Close()

	ctx := context.Background()

	// 第一次发送
	err := svc.SendCode(ctx, "email", "cooldown@example.com", "account-005")
	require.NoError(t, err)

	// 第二次应触发冷却
	err = svc.SendCode(ctx, "email", "cooldown@example.com", "account-005")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "please wait")
}

func TestVerifyCode_CodeReuse(t *testing.T) {
	svc, redis, emailSvc := setupTestVerificationService(t)
	defer redis.Close()

	ctx := context.Background()

	// 发送
	err := svc.SendCode(ctx, "email", "reuse@example.com", "account-006")
	require.NoError(t, err)
	code := emailSvc.sentCodes[0]

	// 第一次验证成功
	accountID, err := svc.VerifyCode(ctx, "email", "reuse@example.com", code)
	require.NoError(t, err)
	assert.Equal(t, "account-006", accountID)

	// 第二次验证应失败（码已被删除）
	_, err = svc.VerifyCode(ctx, "email", "reuse@example.com", code)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired or not found")
}
