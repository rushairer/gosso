package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/cache"
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

	// Revoke Token
	err := service.RevokeToken(ctx, jti, reason, expiresAt)
	require.NoError(t, err)

	// Check if it is revoked
	revoked, err := service.IsTokenRevoked(ctx, jti)
	require.NoError(t, err)
	assert.True(t, revoked)

	// Clean up
	_ = service.RemoveFromBlacklist(ctx, jti)
}

func TestBlacklistService_IsTokenRevoked(t *testing.T) {
	service := setupTestBlacklistService(t)
	defer service.redis.Close()

	ctx := context.Background()
	jti := "test-token-456"

	// Unrevoked Token
	revoked, err := service.IsTokenRevoked(ctx, jti)
	require.NoError(t, err)
	assert.False(t, revoked)

	// Revoke Token
	expiresAt := time.Now().Add(1 * time.Hour)
	err = service.RevokeToken(ctx, jti, "test", expiresAt)
	require.NoError(t, err)

	// Revoked Token
	revoked, err = service.IsTokenRevoked(ctx, jti)
	require.NoError(t, err)
	assert.True(t, revoked)

	// Clean up
	_ = service.RemoveFromBlacklist(ctx, jti)
}

func TestBlacklistService_GetRevokeInfo(t *testing.T) {
	service := setupTestBlacklistService(t)
	defer service.redis.Close()

	ctx := context.Background()
	jti := "test-token-789"
	reason := "account_suspended"
	expiresAt := time.Now().Add(2 * time.Hour)

	// Revoke Token
	err := service.RevokeToken(ctx, jti, reason, expiresAt)
	require.NoError(t, err)

	// Get revoke info
	info, err := service.GetRevokeInfo(ctx, jti)
	require.NoError(t, err)
	assert.Equal(t, jti, info.JTI)
	assert.Equal(t, reason, info.Reason)
	assert.True(t, info.RevokedAt.Before(time.Now().Add(1*time.Second)))
	assert.True(t, info.ExpiresAt.After(time.Now()))

	// Clean up
	_ = service.RemoveFromBlacklist(ctx, jti)
}

func TestBlacklistService_RevokeExpiredToken(t *testing.T) {
	service := setupTestBlacklistService(t)
	defer service.redis.Close()

	ctx := context.Background()
	jti := "test-expired-token"
	reason := "test"
	expiresAt := time.Now().Add(-1 * time.Hour) // Already expired

	// Revoke expired Token (should not be added to the blacklist)
	err := service.RevokeToken(ctx, jti, reason, expiresAt)
	require.NoError(t, err)

	// Check if it is in the blacklist (should not be)
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

	// Revoke Token
	err := service.RevokeToken(ctx, jti, "test", expiresAt)
	require.NoError(t, err)

	// Remove from blacklist
	err = service.RemoveFromBlacklist(ctx, jti)
	require.NoError(t, err)

	// Check if it has been removed
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
	expiresAt := time.Now().Add(2 * time.Second) // Expires after 2 seconds

	// Revoke Token
	err := service.RevokeToken(ctx, jti, reason, expiresAt)
	require.NoError(t, err)

	// Check immediately (should be in the blacklist)
	revoked, err := service.IsTokenRevoked(ctx, jti)
	require.NoError(t, err)
	assert.True(t, revoked)

	// Wait for expiration
	time.Sleep(3 * time.Second)

	// After expiration, it should be automatically removed from the blacklist
	revoked, err = service.IsTokenRevoked(ctx, jti)
	require.NoError(t, err)
	assert.False(t, revoked)
}
