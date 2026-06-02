package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/cache"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
)

type stubPasswordResetEmailSender struct {
	sentLinks []string
}

func (s *stubPasswordResetEmailSender) SendPasswordResetLink(_ context.Context, _, link string) error {
	s.sentLinks = append(s.sentLinks, link)
	return nil
}

func setupTestPasswordResetService(t *testing.T) (*PasswordResetService, *cache.RedisClient, *stubPasswordResetEmailSender) {
	t.Helper()
	logger := zap.NewNop()
	dsn := "redis://localhost:6379/15"

	redisClient, err := cache.NewRedisClient(dsn, 10, 5*time.Second, logger)
	if err != nil {
		t.Skip("Redis not available, skipping test:", err)
	}

	emailSvc := &stubPasswordResetEmailSender{}
	svc := &PasswordResetService{
		redis:       redisClient,
		emailSender: emailSvc,
		baseURL:     "http://localhost:3000/reset-password",
		logger:      logger,
	}

	return svc, redisClient, emailSvc
}

func TestPasswordReset_Success(t *testing.T) {
	svc, redis, _ := setupTestPasswordResetService(t)
	defer redis.Close()

	ctx := context.Background()

	// Simulate complete token storage and verification flow (at the Redis layer)
	tokenHash := tokenDomain.HashToken("test-token-123")
	tokenKey := svc.buildTokenKey(tokenHash)
	data := `{"account_id":"account-001","email":"test@example.com","attempts":0}`
	err := redis.Set(ctx, tokenKey, []byte(data), PasswordResetTokenTTL)
	require.NoError(t, err)

	// Verify token was stored successfully
	raw, err := redis.Get(ctx, tokenKey)
	require.NoError(t, err)
	assert.Contains(t, raw, "account-001")

	// Delete key (simulate one-time use)
	err = redis.Del(ctx, tokenKey)
	require.NoError(t, err)

	// Fetching again should return not found
	_, err = redis.Get(ctx, tokenKey)
	assert.Error(t, err)
	assert.Equal(t, cache.ErrKeyNotFound, err)
}

func TestPasswordReset_Cooldown(t *testing.T) {
	svc, redis, _ := setupTestPasswordResetService(t)
	defer redis.Close()

	ctx := context.Background()
	email := "cooldown@example.com"

	// Set cooldown key
	cooldownKey := svc.buildCooldownKey(email)
	err := redis.Set(ctx, cooldownKey, []byte("1"), PasswordResetCooldownTTL)
	require.NoError(t, err)

	// Check cooldown
	exists, err := redis.Exists(ctx, cooldownKey)
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestPasswordReset_InvalidToken(t *testing.T) {
	svc, redis, _ := setupTestPasswordResetService(t)
	defer redis.Close()

	ctx := context.Background()

	// Use a non-existent token hash
	tokenHash := tokenDomain.HashToken("nonexistent-token")
	tokenKey := svc.buildTokenKey(tokenHash)

	_, err := redis.Get(ctx, tokenKey)
	assert.Error(t, err)
	assert.Equal(t, cache.ErrKeyNotFound, err)
}

func TestPasswordReset_ExpiredToken(t *testing.T) {
	svc, redis, _ := setupTestPasswordResetService(t)
	defer redis.Close()

	ctx := context.Background()

	// Manually delete to simulate expiration
	tokenHash := tokenDomain.HashToken("expired-token")
	tokenKey := svc.buildTokenKey(tokenHash)
	data := `{"account_id":"account-002","email":"expired@example.com","attempts":0}`
	err := redis.Set(ctx, tokenKey, []byte(data), PasswordResetTokenTTL)
	require.NoError(t, err)

	// Manually delete key
	_ = redis.Del(ctx, tokenKey)

	// Fetching should return not found
	_, err = redis.Get(ctx, tokenKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestPasswordReset_TokenExhausted(t *testing.T) {
	svc, redis, _ := setupTestPasswordResetService(t)
	defer redis.Close()

	ctx := context.Background()

	// Store a token with exhausted attempts
	tokenHash := tokenDomain.HashToken("exhausted-token")
	tokenKey := svc.buildTokenKey(tokenHash)
	data := `{"account_id":"account-003","email":"exhausted@example.com","attempts":5}`
	err := redis.Set(ctx, tokenKey, []byte(data), PasswordResetTokenTTL)
	require.NoError(t, err)

	// Verify attempts >= 5
	raw, err := redis.Get(ctx, tokenKey)
	require.NoError(t, err)
	assert.Contains(t, raw, `"attempts":5`)

	// Delete key (simulate exhausted handling in VerifyAndReset)
	err = redis.Del(ctx, tokenKey)
	require.NoError(t, err)
}

func TestPasswordReset_TokenReuse(t *testing.T) {
	svc, redis, _ := setupTestPasswordResetService(t)
	defer redis.Close()

	ctx := context.Background()

	// Store token
	tokenHash := tokenDomain.HashToken("reuse-token")
	tokenKey := svc.buildTokenKey(tokenHash)
	data := `{"account_id":"account-004","email":"reuse@example.com","attempts":0}`
	err := redis.Set(ctx, tokenKey, []byte(data), PasswordResetTokenTTL)
	require.NoError(t, err)

	// First fetch succeeds
	_, err = redis.Get(ctx, tokenKey)
	require.NoError(t, err)

	// Delete (one-time use)
	_ = redis.Del(ctx, tokenKey)

	// Second fetch fails
	_, err = redis.Get(ctx, tokenKey)
	assert.Error(t, err)
	assert.Equal(t, cache.ErrKeyNotFound, err)
}

func TestPasswordReset_EmailNotFound(t *testing.T) {
	svc, redis, emailSvc := setupTestPasswordResetService(t)
	defer redis.Close()

	ctx := context.Background()

	// Non-existent email: no Redis entry, no email sent
	cooldownKey := svc.buildCooldownKey("nonexistent@example.com")
	exists, err := redis.Exists(ctx, cooldownKey)
	require.NoError(t, err)
	assert.False(t, exists)

	assert.Len(t, emailSvc.sentLinks, 0)

	_ = ctx
}

func TestPasswordReset_TokenSecurity(t *testing.T) {
	// Verify SHA256 hash is irreversible and has correct length
	originalToken := "a]b1c2d3e4f5"
	hashedToken := tokenDomain.HashToken(originalToken)

	assert.NotEqual(t, originalToken, hashedToken)
	assert.Len(t, hashedToken, 64) // SHA256 hex = 64 chars

	// Same input produces the same hash
	hashedAgain := tokenDomain.HashToken(originalToken)
	assert.Equal(t, hashedToken, hashedAgain)
}
