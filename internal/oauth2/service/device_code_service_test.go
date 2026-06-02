package service

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/oauth2/domain"
)

func setupDeviceCodeService(t *testing.T) *DeviceCodeService {
	t.Helper()

	redisDSN := os.Getenv("GOUNO_REDIS_DSN")
	if redisDSN == "" {
		redisDSN = "127.0.0.1:6379"
	}

	redis, err := cache.NewRedisClient(redisDSN, 10, 5*time.Second, zap.NewNop())
	if err != nil {
		t.Skipf("Redis not available at %s: %v", redisDSN, err)
	}
	t.Cleanup(func() { redis.Close() })

	return NewDeviceCodeService(redis, zap.NewNop(), 10*time.Minute, 5*time.Second)
}

func TestDeviceCodeService_CreateAndGet(t *testing.T) {
	svc := setupDeviceCodeService(t)
	ctx := context.Background()

	dc, err := svc.CreateDeviceCode(ctx, "test-client", []string{"openid", "profile"})
	require.NoError(t, err)
	require.NotNil(t, dc)

	assert.Len(t, dc.DeviceCode, 64) // 32 bytes → 64 hex chars
	assert.Regexp(t, `^[A-Z2-9]{4}-[A-Z2-9]{4}$`, dc.UserCode)
	assert.Equal(t, "test-client", dc.ClientID)
	assert.Equal(t, []string{"openid", "profile"}, dc.Scopes)
	assert.Equal(t, domain.DeviceCodeStatusPending, dc.Status)
	assert.True(t, dc.ExpiresAt.After(time.Now()))
	assert.Equal(t, 5, dc.Interval)

	// Retrieve by device code
	fetched, err := svc.GetDeviceCode(ctx, dc.DeviceCode)
	require.NoError(t, err)
	assert.Equal(t, dc.DeviceCode, fetched.DeviceCode)
	assert.Equal(t, dc.UserCode, fetched.UserCode)
}

func TestDeviceCodeService_GetByUserCode(t *testing.T) {
	svc := setupDeviceCodeService(t)
	ctx := context.Background()

	dc, err := svc.CreateDeviceCode(ctx, "test-client", []string{"openid"})
	require.NoError(t, err)

	fetched, err := svc.GetDeviceCodeByUserCode(ctx, dc.UserCode)
	require.NoError(t, err)
	assert.Equal(t, dc.DeviceCode, fetched.DeviceCode)

	// Also test without dash
	userCodeNoDash := dc.UserCode[:4] + dc.UserCode[5:]
	fetched2, err := svc.GetDeviceCodeByUserCode(ctx, userCodeNoDash)
	require.NoError(t, err)
	assert.Equal(t, dc.DeviceCode, fetched2.DeviceCode)
}

func TestDeviceCodeService_GetDeviceCode_NotFound(t *testing.T) {
	svc := setupDeviceCodeService(t)
	ctx := context.Background()

	_, err := svc.GetDeviceCode(ctx, "nonexistent")
	assert.ErrorIs(t, err, domain.ErrDeviceCodeNotFound)
}

func TestDeviceCodeService_Authorize(t *testing.T) {
	svc := setupDeviceCodeService(t)
	ctx := context.Background()

	dc, err := svc.CreateDeviceCode(ctx, "test-client", []string{"openid"})
	require.NoError(t, err)

	err = svc.AuthorizeDeviceCode(ctx, dc.DeviceCode, "account-123")
	require.NoError(t, err)

	fetched, err := svc.GetDeviceCode(ctx, dc.DeviceCode)
	require.NoError(t, err)
	assert.Equal(t, domain.DeviceCodeStatusAuthorized, fetched.Status)
	assert.Equal(t, "account-123", fetched.AccountID)
}

func TestDeviceCodeService_Deny(t *testing.T) {
	svc := setupDeviceCodeService(t)
	ctx := context.Background()

	dc, err := svc.CreateDeviceCode(ctx, "test-client", []string{"openid"})
	require.NoError(t, err)

	err = svc.DenyDeviceCode(ctx, dc.DeviceCode)
	require.NoError(t, err)

	fetched, err := svc.GetDeviceCode(ctx, dc.DeviceCode)
	require.NoError(t, err)
	assert.Equal(t, domain.DeviceCodeStatusDenied, fetched.Status)
}

func TestDeviceCodeService_PollRate(t *testing.T) {
	svc := setupDeviceCodeService(t)
	ctx := context.Background()

	dc, err := svc.CreateDeviceCode(ctx, "test-client", []string{"openid"})
	require.NoError(t, err)

	// First poll should succeed
	err = svc.CheckAndUpdatePollRate(ctx, dc.DeviceCode)
	require.NoError(t, err)

	// Immediate second poll should be slow_down
	err = svc.CheckAndUpdatePollRate(ctx, dc.DeviceCode)
	assert.ErrorIs(t, err, domain.ErrSlowDown)
}

func TestDeviceCodeService_MarkUsed(t *testing.T) {
	svc := setupDeviceCodeService(t)
	ctx := context.Background()

	dc, err := svc.CreateDeviceCode(ctx, "test-client", []string{"openid"})
	require.NoError(t, err)

	err = svc.MarkUsed(ctx, dc.DeviceCode)
	require.NoError(t, err)

	fetched, err := svc.GetDeviceCode(ctx, dc.DeviceCode)
	require.NoError(t, err)
	assert.Equal(t, domain.DeviceCodeStatusUsed, fetched.Status)
}
