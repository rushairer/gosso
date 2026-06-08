package service

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/testutil"
)

func setupTestBlacklistService(t *testing.T) (*BlacklistService, func(), *miniredis.Miniredis) {
	t.Helper()
	logger := zap.NewNop()

	redisClient, mr := testutil.SetupTestRedis(t)
	cleanup := mr.Close

	service := NewBlacklistService(redisClient, logger)

	return service, cleanup, mr
}

func TestBlacklistService_RevokeToken(t *testing.T) {
	service, cleanup, _ := setupTestBlacklistService(t)
	defer cleanup()

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
	_ = service.removeFromBlacklist(ctx, jti)
}

func TestBlacklistService_IsTokenRevoked(t *testing.T) {
	service, cleanup, _ := setupTestBlacklistService(t)
	defer cleanup()

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
	_ = service.removeFromBlacklist(ctx, jti)
}

func TestBlacklistService_GetRevokeInfo(t *testing.T) {
	service, cleanup, _ := setupTestBlacklistService(t)
	defer cleanup()

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
	_ = service.removeFromBlacklist(ctx, jti)
}

func TestBlacklistService_RevokeExpiredToken(t *testing.T) {
	service, cleanup, _ := setupTestBlacklistService(t)
	defer cleanup()

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

func TestBlacklistService_removeFromBlacklist(t *testing.T) {
	service, cleanup, _ := setupTestBlacklistService(t)
	defer cleanup()

	ctx := context.Background()
	jti := "test-token-remove"
	expiresAt := time.Now().Add(1 * time.Hour)

	// Revoke Token
	err := service.RevokeToken(ctx, jti, "test", expiresAt)
	require.NoError(t, err)

	// Remove from blacklist
	err = service.removeFromBlacklist(ctx, jti)
	require.NoError(t, err)

	// Check if it has been removed
	revoked, err := service.IsTokenRevoked(ctx, jti)
	require.NoError(t, err)
	assert.False(t, revoked)
}

func TestBlacklistService_AutoExpiration(t *testing.T) {
	service, cleanup, mr := setupTestBlacklistService(t)
	defer cleanup()

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

	// Fast-forward miniredis past expiration (2s token TTL + 5min buffer)
	mr.FastForward(5*time.Minute + 3*time.Second)

	// After expiration, it should be automatically removed from the blacklist
	revoked, err = service.IsTokenRevoked(ctx, jti)
	require.NoError(t, err)
	assert.False(t, revoked)
}

// ──────────────────────────────────────────────
// Account-level revocation tests
// ──────────────────────────────────────────────

func TestBlacklistService_SetAccountRevokedAfter(t *testing.T) {
	service, cleanup, _ := setupTestBlacklistService(t)
	defer cleanup()

	ctx := context.Background()
	accountID := "acct-set-revoke"
	revokedAt := time.Now().Truncate(time.Second)
	ttl := 1 * time.Hour

	err := service.SetAccountRevokedAfter(ctx, accountID, revokedAt, ttl)
	require.NoError(t, err)

	got, err := service.GetAccountRevokedAfter(ctx, accountID)
	require.NoError(t, err)
	assert.Equal(t, revokedAt.Unix(), got.Unix())
}

func TestBlacklistService_GetAccountRevokedAfter_NotSet(t *testing.T) {
	service, cleanup, _ := setupTestBlacklistService(t)
	defer cleanup()

	ctx := context.Background()

	got, err := service.GetAccountRevokedAfter(ctx, "acct-never-set")
	require.NoError(t, err)
	assert.True(t, got.IsZero())
}

func TestBlacklistService_GetRevokeInfo_NotRevoked(t *testing.T) {
	service, cleanup, _ := setupTestBlacklistService(t)
	defer cleanup()

	ctx := context.Background()

	_, err := service.GetRevokeInfo(ctx, "nonexistent-jti")
	assert.ErrorIs(t, err, ErrTokenNotRevoked)
}
