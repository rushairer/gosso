package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/oauth2/domain"
	"github.com/rushairer/gosso/internal/testutil"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
)

// setupDeviceCodeServiceBase creates a DeviceCodeService backed by miniredis
// WITHOUT checking for cjson support. Use this for tests that only need
// plain Redis commands (SET/GET) and no cjson-based Lua scripts.
func setupDeviceCodeServiceBase(t *testing.T) *DeviceCodeService {
	t.Helper()

	redis, mr := testutil.SetupTestRedis(t)
	t.Cleanup(mr.Close)

	return NewDeviceCodeService(redis, zap.NewNop(), 10*time.Minute, 5*time.Second)
}

// setupDeviceCodeServiceCJSON is like setupDeviceCodeServiceBase but skips
// the test when the Redis instance does not support the Lua cjson module.
// Required for AuthorizeDeviceCode, DenyDeviceCode, CheckAndUpdatePollRate,
// and ClaimAuthorizedDeviceCode which use cjson in their Lua scripts.
func setupDeviceCodeServiceCJSON(t *testing.T) *DeviceCodeService {
	t.Helper()
	svc := setupDeviceCodeServiceBase(t)
	testutil.SkipIfNoCJSON(t, svc.redis)
	return svc
}

func TestDeviceCodeService_CreateAndGet(t *testing.T) {
	svc := setupDeviceCodeServiceBase(t)
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

	// Retrieve by device code — raw device code is not stored in Redis (security: S1)
	fetched, err := svc.GetDeviceCode(ctx, dc.DeviceCode)
	require.NoError(t, err)
	assert.Empty(t, fetched.DeviceCode)
	assert.Equal(t, dc.UserCode, fetched.UserCode)
}

func TestDeviceCodeService_GetByUserCode(t *testing.T) {
	svc := setupDeviceCodeServiceBase(t)
	ctx := context.Background()

	dc, err := svc.CreateDeviceCode(ctx, "test-client", []string{"openid"})
	require.NoError(t, err)

	fetched, err := svc.GetDeviceCodeByUserCode(ctx, dc.UserCode)
	require.NoError(t, err)
	assert.Equal(t, dc.ClientID, fetched.ClientID)

	// Also test without dash
	userCodeNoDash := dc.UserCode[:4] + dc.UserCode[5:]
	fetched2, err := svc.GetDeviceCodeByUserCode(ctx, userCodeNoDash)
	require.NoError(t, err)
	assert.Equal(t, dc.ClientID, fetched2.ClientID)
}

func TestDeviceCodeService_GetDeviceCode_NotFound(t *testing.T) {
	svc := setupDeviceCodeServiceBase(t)
	ctx := context.Background()

	_, err := svc.GetDeviceCode(ctx, "nonexistent")
	assert.ErrorIs(t, err, domain.ErrDeviceCodeNotFound)
}

func TestDeviceCodeService_Authorize(t *testing.T) {
	svc := setupDeviceCodeServiceCJSON(t)
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
	svc := setupDeviceCodeServiceCJSON(t)
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
	svc := setupDeviceCodeServiceCJSON(t)
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

// ──────────────────────────────────────────────
// NewDeviceCodeService defaults
// ──────────────────────────────────────────────

func TestNewDeviceCodeService_Defaults(t *testing.T) {
	svc := NewDeviceCodeService(nil, nil, 0, 0)
	assert.NotNil(t, svc)
	assert.NotNil(t, svc.logger)
	assert.Equal(t, 10*time.Minute, svc.expiry)
	assert.Equal(t, 5*time.Second, svc.interval)
}

func TestNewDeviceCodeService_ExplicitValues(t *testing.T) {
	svc := NewDeviceCodeService(nil, zap.NewNop(), 2*time.Minute, 10*time.Second)
	assert.Equal(t, 2*time.Minute, svc.expiry)
	assert.Equal(t, 10*time.Second, svc.interval)
}

// ──────────────────────────────────────────────
// generateUserCode (pure function)
// ──────────────────────────────────────────────

func TestGenerateUserCode_Length8(t *testing.T) {
	code, err := generateUserCode(8)
	require.NoError(t, err)
	assert.Len(t, code, 8)
	// All characters must be from the userCodeCharset
	for _, c := range code {
		assert.Contains(t, userCodeCharset, string(c))
	}
}

func TestGenerateUserCode_Length4(t *testing.T) {
	code, err := generateUserCode(4)
	require.NoError(t, err)
	assert.Len(t, code, 4)
}

func TestGenerateUserCode_Uniqueness(t *testing.T) {
	seen := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		code, err := generateUserCode(8)
		require.NoError(t, err)
		seen[code] = true
	}
	// With 8 chars from 31-char charset, collisions in 100 draws are astronomically unlikely
	assert.Len(t, seen, 100)
}

func TestGetDeviceCode_CorruptData(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()
	svc := NewDeviceCodeService(redisClient, zap.NewNop(), 10*time.Minute, 5*time.Second)
	ctx := context.Background()

	dc, err := svc.CreateDeviceCode(ctx, "client", []string{"openid"})
	require.NoError(t, err)

	// Corrupt the stored device code data
	key := DeviceCodeKeyPrefix + tokenDomain.HashToken(dc.DeviceCode)
	mr.Set(key, "not-valid-json")

	_, err = svc.GetDeviceCode(ctx, dc.DeviceCode)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal device code")
}

func TestGetDeviceCodeByUserCode_WrongLength(t *testing.T) {
	svc := setupDeviceCodeServiceBase(t)
	ctx := context.Background()

	_, err := svc.GetDeviceCodeByUserCode(ctx, "ABC")
	assert.ErrorIs(t, err, domain.ErrDeviceCodeNotFound)

	_, err = svc.GetDeviceCodeByUserCode(ctx, "ABCDEFGHIJ")
	assert.ErrorIs(t, err, domain.ErrDeviceCodeNotFound)
}

func TestGetDeviceCodeByUserCode_NotFound(t *testing.T) {
	svc := setupDeviceCodeServiceBase(t)
	ctx := context.Background()

	_, err := svc.GetDeviceCodeByUserCode(ctx, "ABCD1234")
	assert.ErrorIs(t, err, domain.ErrDeviceCodeNotFound)
}

func TestGetDeviceCodeByUserCode_CorruptDeviceCode(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()
	svc := NewDeviceCodeService(redisClient, zap.NewNop(), 10*time.Minute, 5*time.Second)
	ctx := context.Background()

	dc, err := svc.CreateDeviceCode(ctx, "client", []string{"openid"})
	require.NoError(t, err)

	// Corrupt the device code data (user code mapping still points to it)
	dcKey := DeviceCodeKeyPrefix + tokenDomain.HashToken(dc.DeviceCode)
	mr.Set(dcKey, "not-valid-json")

	_, err = svc.GetDeviceCodeByUserCode(ctx, dc.UserCode)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal device code")
}

// ──────────────────────────────────────────────
// AuthorizeDeviceCode / DenyDeviceCode / CheckAndUpdatePollRate
// not-found via TTL pre-check (no cjson required)
// ──────────────────────────────────────────────

func TestAuthorizeDeviceCode_NotFound(t *testing.T) {
	svc := setupDeviceCodeServiceBase(t)
	ctx := context.Background()

	err := svc.AuthorizeDeviceCode(ctx, "nonexistent-device-code", "account-123")
	assert.ErrorIs(t, err, domain.ErrDeviceCodeNotFound)
}

func TestDenyDeviceCode_NotFound(t *testing.T) {
	svc := setupDeviceCodeServiceBase(t)
	ctx := context.Background()

	err := svc.DenyDeviceCode(ctx, "nonexistent-device-code")
	assert.ErrorIs(t, err, domain.ErrDeviceCodeNotFound)
}

func TestCheckAndUpdatePollRate_NotFound(t *testing.T) {
	svc := setupDeviceCodeServiceBase(t)
	ctx := context.Background()

	err := svc.CheckAndUpdatePollRate(ctx, "nonexistent-device-code")
	assert.ErrorIs(t, err, domain.ErrDeviceCodeNotFound)
}

// ──────────────────────────────────────────────
// ClaimAuthorizedDeviceCode (requires cjson)
// ──────────────────────────────────────────────

func TestClaimAuthorizedDeviceCode_Success(t *testing.T) {
	svc := setupDeviceCodeServiceCJSON(t)
	ctx := context.Background()

	dc, err := svc.CreateDeviceCode(ctx, "test-client", []string{"openid"})
	require.NoError(t, err)

	err = svc.AuthorizeDeviceCode(ctx, dc.DeviceCode, "account-123")
	require.NoError(t, err)

	claimed, err := svc.ClaimAuthorizedDeviceCode(ctx, dc.DeviceCode, "test-client")
	require.NoError(t, err)
	assert.Equal(t, domain.DeviceCodeStatusUsed, claimed.Status)
	assert.Equal(t, "account-123", claimed.AccountID)
}

func TestClaimAuthorizedDeviceCode_AlreadyUsed(t *testing.T) {
	svc := setupDeviceCodeServiceCJSON(t)
	ctx := context.Background()

	dc, err := svc.CreateDeviceCode(ctx, "test-client", []string{"openid"})
	require.NoError(t, err)

	err = svc.AuthorizeDeviceCode(ctx, dc.DeviceCode, "account-123")
	require.NoError(t, err)

	_, err = svc.ClaimAuthorizedDeviceCode(ctx, dc.DeviceCode, "test-client")
	require.NoError(t, err)

	// Double-claim must be rejected
	_, err = svc.ClaimAuthorizedDeviceCode(ctx, dc.DeviceCode, "test-client")
	assert.ErrorIs(t, err, domain.ErrDeviceCodeNotFound)
}

func TestClaimAuthorizedDeviceCode_PendingNotClaimable(t *testing.T) {
	svc := setupDeviceCodeServiceCJSON(t)
	ctx := context.Background()

	dc, err := svc.CreateDeviceCode(ctx, "test-client", []string{"openid"})
	require.NoError(t, err)

	// Code is still pending — not yet authorized
	_, err = svc.ClaimAuthorizedDeviceCode(ctx, dc.DeviceCode, "test-client")
	assert.ErrorIs(t, err, domain.ErrDeviceCodeNotFound)
}

func TestClaimAuthorizedDeviceCode_DeniedNotClaimable(t *testing.T) {
	svc := setupDeviceCodeServiceCJSON(t)
	ctx := context.Background()

	dc, err := svc.CreateDeviceCode(ctx, "test-client", []string{"openid"})
	require.NoError(t, err)

	err = svc.DenyDeviceCode(ctx, dc.DeviceCode)
	require.NoError(t, err)

	// Denied code cannot be claimed
	_, err = svc.ClaimAuthorizedDeviceCode(ctx, dc.DeviceCode, "test-client")
	assert.ErrorIs(t, err, domain.ErrDeviceCodeNotFound)
}

// ──────────────────────────────────────────────
// State-machine transitions (requires cjson)
// ──────────────────────────────────────────────

func TestAuthorizeDeviceCode_AlreadyDenied(t *testing.T) {
	svc := setupDeviceCodeServiceCJSON(t)
	ctx := context.Background()

	dc, err := svc.CreateDeviceCode(ctx, "test-client", []string{"openid"})
	require.NoError(t, err)

	err = svc.DenyDeviceCode(ctx, dc.DeviceCode)
	require.NoError(t, err)

	// Cannot authorize a denied code
	err = svc.AuthorizeDeviceCode(ctx, dc.DeviceCode, "account-123")
	assert.ErrorIs(t, err, domain.ErrDeviceCodeNotFound)
}

func TestDenyDeviceCode_AlreadyAuthorized(t *testing.T) {
	svc := setupDeviceCodeServiceCJSON(t)
	ctx := context.Background()

	dc, err := svc.CreateDeviceCode(ctx, "test-client", []string{"openid"})
	require.NoError(t, err)

	err = svc.AuthorizeDeviceCode(ctx, dc.DeviceCode, "account-123")
	require.NoError(t, err)

	// Cannot deny an authorized code
	err = svc.DenyDeviceCode(ctx, dc.DeviceCode)
	assert.ErrorIs(t, err, domain.ErrDeviceCodeNotFound)
}

// ──────────────────────────────────────────────
// Script error paths (miniredis doesn't support cjson)
// These exercise the code paths between TTL check and RunScript result
// handling. If miniredis adds cjson support, convert to CJSON tests.
// ──────────────────────────────────────────────

func TestClaimAuthorizedDeviceCode_ScriptError(t *testing.T) {
	svc := setupDeviceCodeServiceBase(t)
	ctx := context.Background()

	dc, err := svc.CreateDeviceCode(ctx, "test-client", []string{"openid"})
	require.NoError(t, err)

	// claimAuthorizedScript uses cjson which fails on miniredis
	claimed, err := svc.ClaimAuthorizedDeviceCode(ctx, dc.DeviceCode, "test-client")
	assert.ErrorIs(t, err, domain.ErrDeviceCodeNotFound)
	assert.Nil(t, claimed)
}

func TestAuthorizeDeviceCode_ScriptError(t *testing.T) {
	svc := setupDeviceCodeServiceBase(t)
	ctx := context.Background()

	dc, err := svc.CreateDeviceCode(ctx, "test-client", []string{"openid"})
	require.NoError(t, err)

	// authorizeDeviceCodeScript uses cjson which fails on miniredis
	err = svc.AuthorizeDeviceCode(ctx, dc.DeviceCode, "account-123")
	assert.ErrorIs(t, err, domain.ErrDeviceCodeNotFound)
}

func TestDenyDeviceCode_ScriptError(t *testing.T) {
	svc := setupDeviceCodeServiceBase(t)
	ctx := context.Background()

	dc, err := svc.CreateDeviceCode(ctx, "test-client", []string{"openid"})
	require.NoError(t, err)

	// denyDeviceCodeScript uses cjson which fails on miniredis
	err = svc.DenyDeviceCode(ctx, dc.DeviceCode)
	assert.ErrorIs(t, err, domain.ErrDeviceCodeNotFound)
}

func TestCheckAndUpdatePollRate_ScriptError(t *testing.T) {
	svc := setupDeviceCodeServiceBase(t)
	ctx := context.Background()

	dc, err := svc.CreateDeviceCode(ctx, "test-client", []string{"openid"})
	require.NoError(t, err)

	// checkAndUpdatePollRateScript uses cjson which fails on miniredis
	err = svc.CheckAndUpdatePollRate(ctx, dc.DeviceCode)
	assert.ErrorIs(t, err, domain.ErrDeviceCodeNotFound)
}

// ──────────────────────────────────────────────
// Redis connection error paths
// ──────────────────────────────────────────────

func TestCreateDeviceCode_RedisError(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	svc := NewDeviceCodeService(redisClient, zap.NewNop(), 10*time.Minute, 5*time.Second)
	ctx := context.Background()

	mr.Close()

	_, err := svc.CreateDeviceCode(ctx, "test-client", []string{"openid"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "store device code")
}

func TestGetDeviceCode_RedisError(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	svc := NewDeviceCodeService(redisClient, zap.NewNop(), 10*time.Minute, 5*time.Second)
	ctx := context.Background()

	dc, err := svc.CreateDeviceCode(ctx, "test-client", []string{"openid"})
	require.NoError(t, err)

	mr.Close()

	_, err = svc.GetDeviceCode(ctx, dc.DeviceCode)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get device code")
}

func TestGetDeviceCodeByUserCode_ResolveError(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	svc := NewDeviceCodeService(redisClient, zap.NewNop(), 10*time.Minute, 5*time.Second)
	ctx := context.Background()

	dc, err := svc.CreateDeviceCode(ctx, "test-client", []string{"openid"})
	require.NoError(t, err)

	mr.Close()

	_, err = svc.GetDeviceCodeByUserCode(ctx, dc.UserCode)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "resolve user code")
}

func TestAuthorizeDeviceCode_RedisDown(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	svc := NewDeviceCodeService(redisClient, zap.NewNop(), 10*time.Minute, 5*time.Second)
	ctx := context.Background()

	_, err := svc.CreateDeviceCode(ctx, "test-client", []string{"openid"})
	require.NoError(t, err)

	mr.Close()

	err = svc.AuthorizeDeviceCode(ctx, "nonexistent", "account-123")
	assert.Error(t, err)
}

func TestDenyDeviceCode_RedisDown(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	svc := NewDeviceCodeService(redisClient, zap.NewNop(), 10*time.Minute, 5*time.Second)
	ctx := context.Background()

	_, err := svc.CreateDeviceCode(ctx, "test-client", []string{"openid"})
	require.NoError(t, err)

	mr.Close()

	err = svc.DenyDeviceCode(ctx, "nonexistent")
	assert.Error(t, err)
}

func TestCheckAndUpdatePollRate_RedisDown(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	svc := NewDeviceCodeService(redisClient, zap.NewNop(), 10*time.Minute, 5*time.Second)
	ctx := context.Background()

	_, err := svc.CreateDeviceCode(ctx, "test-client", []string{"openid"})
	require.NoError(t, err)

	mr.Close()

	err = svc.CheckAndUpdatePollRate(ctx, "nonexistent")
	assert.Error(t, err)
}
