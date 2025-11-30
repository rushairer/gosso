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

func setupTestBlacklistService(t *testing.T) *BlacklistService {
	logger := zap.NewNop()
	dsn := "redis://localhost:6379/15"
	
	redisClient, err := cache.NewRedisClient(dsn, 10, 5*time.Second, logger)
	if err != nil {
		t.Skip("Redis not available, skipping test:", err)
	}
	
	service := NewBlacklistService(redisClient, logger)
	
	return service
}

func TestBlacklistService_RevokeToken(t *testing.T) {
	service := setupTestBlacklistService(t)
	defer service.redis.Close()

	ctx := context.Background()
	jti := "test-token-123"
	reason := "user_logout"
	expiresAt := time.Now().Add(1 * time.Hour)

	// 撤销 Token
	err := service.RevokeToken(ctx, jti, reason, expiresAt)
	require.NoError(t, err)

	// 检查是否已撤销
	revoked, err := service.IsTokenRevoked(ctx, jti)
	require.NoError(t, err)
	assert.True(t, revoked)

	// 清理
	_ = service.RemoveFromBlacklist(ctx, jti)
}

func TestBlacklistService_IsTokenRevoked(t *testing.T) {
	service := setupTestBlacklistService(t)
	defer service.redis.Close()

	ctx := context.Background()
	jti := "test-token-456"

	// 未撤销的 Token
	revoked, err := service.IsTokenRevoked(ctx, jti)
	require.NoError(t, err)
	assert.False(t, revoked)

	// 撤销 Token
	expiresAt := time.Now().Add(1 * time.Hour)
	err = service.RevokeToken(ctx, jti, "test", expiresAt)
	require.NoError(t, err)

	// 已撤销的 Token
	revoked, err = service.IsTokenRevoked(ctx, jti)
	require.NoError(t, err)
	assert.True(t, revoked)

	// 清理
	_ = service.RemoveFromBlacklist(ctx, jti)
}

func TestBlacklistService_GetRevokeInfo(t *testing.T) {
	service := setupTestBlacklistService(t)
	defer service.redis.Close()

	ctx := context.Background()
	jti := "test-token-789"
	reason := "account_suspended"
	expiresAt := time.Now().Add(2 * time.Hour)

	// 撤销 Token
	err := service.RevokeToken(ctx, jti, reason, expiresAt)
	require.NoError(t, err)

	// 获取撤销信息
	info, err := service.GetRevokeInfo(ctx, jti)
	require.NoError(t, err)
	assert.Equal(t, jti, info.JTI)
	assert.Equal(t, reason, info.Reason)
	assert.True(t, info.RevokedAt.Before(time.Now().Add(1*time.Second)))
	assert.True(t, info.ExpiresAt.After(time.Now()))

	// 清理
	_ = service.RemoveFromBlacklist(ctx, jti)
}

func TestBlacklistService_RevokeExpiredToken(t *testing.T) {
	service := setupTestBlacklistService(t)
	defer service.redis.Close()

	ctx := context.Background()
	jti := "test-expired-token"
	reason := "test"
	expiresAt := time.Now().Add(-1 * time.Hour) // 已过期

	// 撤销已过期的 Token（应该不加入黑名单）
	err := service.RevokeToken(ctx, jti, reason, expiresAt)
	require.NoError(t, err)

	// 检查是否在黑名单中（应该不在）
	revoked, err := service.IsTokenRevoked(ctx, jti)
	require.NoError(t, err)
	assert.False(t, revoked)
}

func TestBlacklistService_RemoveFromBlacklist(t *testing.T) {
	service := setupTestBlacklistService(t)
	defer service.redis.Close()

	ctx := context.Background()
	jti := "test-token-remove"
	expiresAt := time.Now().Add(1 * time.Hour)

	// 撤销 Token
	err := service.RevokeToken(ctx, jti, "test", expiresAt)
	require.NoError(t, err)

	// 从黑名单移除
	err = service.RemoveFromBlacklist(ctx, jti)
	require.NoError(t, err)

	// 检查是否已移除
	revoked, err := service.IsTokenRevoked(ctx, jti)
	require.NoError(t, err)
	assert.False(t, revoked)
}

func TestBlacklistService_AutoExpiration(t *testing.T) {
	service := setupTestBlacklistService(t)
	defer service.redis.Close()

	ctx := context.Background()
	jti := "test-token-auto-expire"
	reason := "test"
	expiresAt := time.Now().Add(2 * time.Second) // 2秒后过期

	// 撤销 Token
	err := service.RevokeToken(ctx, jti, reason, expiresAt)
	require.NoError(t, err)

	// 立即检查（应该在黑名单中）
	revoked, err := service.IsTokenRevoked(ctx, jti)
	require.NoError(t, err)
	assert.True(t, revoked)

	// 等待过期
	time.Sleep(3 * time.Second)

	// 过期后应该自动从黑名单移除
	revoked, err = service.IsTokenRevoked(ctx, jti)
	require.NoError(t, err)
	assert.False(t, revoked)
}
