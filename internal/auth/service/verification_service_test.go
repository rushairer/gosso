package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/testutil"
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

func setupTestVerificationService(t *testing.T) (*VerificationService, *cache.RedisClient, func(), *stubEmailService) {
	t.Helper()
	logger := zap.NewNop()

	redisClient, mr := testutil.SetupTestRedis(t)
	testutil.SkipIfNoCJSON(t, redisClient)
	cleanup := mr.Close

	emailSvc := &stubEmailService{}
	smsSvc := &stubSMSService{}
	svc := NewVerificationService(redisClient, emailSvc, smsSvc, nil, logger)

	return svc, redisClient, cleanup, emailSvc
}

func TestVerifyCode_Success(t *testing.T) {
	svc, _, cleanup, emailSvc := setupTestVerificationService(t)
	defer cleanup()

	ctx := context.Background()

	// Send verification code
	err := svc.SendCode(ctx, "email", "test@example.com", "account-001")
	require.NoError(t, err)
	require.Len(t, emailSvc.sentCodes, 1)
	code := emailSvc.sentCodes[0]

	// Verify
	accountID, err := svc.VerifyCode(ctx, "email", "test@example.com", code)
	require.NoError(t, err)
	assert.Equal(t, "account-001", accountID)
}

func TestVerifyCode_Wrong(t *testing.T) {
	svc, _, cleanup, _ := setupTestVerificationService(t)
	defer cleanup()

	ctx := context.Background()

	// Send verification code
	err := svc.SendCode(ctx, "email", "wrong@example.com", "account-002")
	require.NoError(t, err)

	// Incorrect verification code
	_, err = svc.VerifyCode(ctx, "email", "wrong@example.com", "000000")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid verification code")
}

func TestVerifyCode_Exhausted(t *testing.T) {
	svc, _, cleanup, _ := setupTestVerificationService(t)
	defer cleanup()

	ctx := context.Background()

	// Send verification code
	err := svc.SendCode(ctx, "email", "exhaust@example.com", "account-003")
	require.NoError(t, err)

	// 5 incorrect attempts
	for i := 0; i < 5; i++ {
		_, _ = svc.VerifyCode(ctx, "email", "exhaust@example.com", "wrong")
	}

	// 6th attempt should return exhausted
	_, err = svc.VerifyCode(ctx, "email", "exhaust@example.com", "wrong")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exhausted")
}

func TestVerifyCode_Expired(t *testing.T) {
	svc, redis, cleanup, emailSvc := setupTestVerificationService(t)
	defer cleanup()

	ctx := context.Background()

	// Send verification code
	err := svc.SendCode(ctx, "email", "expired@example.com", "account-004")
	require.NoError(t, err)

	// Manually delete key to simulate expiration
	codeKey := svc.buildCodeKey("email", "expired@example.com")
	_ = redis.Del(ctx, codeKey)

	// Verify
	_, err = svc.VerifyCode(ctx, "email", "expired@example.com", emailSvc.sentCodes[0])
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired or not found")
}

func TestSendCode_Cooldown(t *testing.T) {
	svc, _, cleanup, _ := setupTestVerificationService(t)
	defer cleanup()

	ctx := context.Background()

	// First send
	err := svc.SendCode(ctx, "email", "cooldown@example.com", "account-005")
	require.NoError(t, err)

	// Second send should trigger cooldown
	err = svc.SendCode(ctx, "email", "cooldown@example.com", "account-005")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "please wait")
}

func TestVerifyCode_CodeReuse(t *testing.T) {
	svc, _, cleanup, emailSvc := setupTestVerificationService(t)
	defer cleanup()

	ctx := context.Background()

	// Send
	err := svc.SendCode(ctx, "email", "reuse@example.com", "account-006")
	require.NoError(t, err)
	code := emailSvc.sentCodes[0]

	// 1st verification succeeds
	accountID, err := svc.VerifyCode(ctx, "email", "reuse@example.com", code)
	require.NoError(t, err)
	assert.Equal(t, "account-006", accountID)

	// 2nd verification should fail (code has been deleted)
	_, err = svc.VerifyCode(ctx, "email", "reuse@example.com", code)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired or not found")
}
