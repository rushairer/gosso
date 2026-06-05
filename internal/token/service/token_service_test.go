package service

import (
	"context"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/token/domain"
)

func setupTestTokenService(t *testing.T) (*TokenService, *cache.RedisClient) {
	t.Helper()
	logger := zap.NewNop()
	dsn := "redis://localhost:6379/15"

	redisClient, err := cache.NewRedisClient(dsn, 10, 5*time.Second, logger)
	if err != nil {
		t.Skip("Redis not available, skipping test:", err)
	}

	keySvc, err := NewKeyService("", "", logger)
	require.NoError(t, err)

	blacklist := NewBlacklistService(redisClient, logger)
	svc := NewTokenService(
		keySvc,
		"http://localhost:8080",
		15*time.Minute,
		7*24*time.Hour,
		redisClient,
		blacklist,
		logger,
	)

	return svc, redisClient
}

func TestGenerateAccessToken_RS256(t *testing.T) {
	svc, redis := setupTestTokenService(t)
	defer redis.Close()

	claims := &domain.AccessTokenClaims{
		AccountID: "account-001",
		Roles:     []string{"admin"},
		SessionID: "session-001",
	}

	tokenString, err := svc.GenerateAccessToken(claims)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	// Parse token to verify alg and kid header
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenString, &domain.AccessTokenClaims{})
	require.NoError(t, err)

	assert.Equal(t, "RS256", token.Header["alg"])
	assert.Equal(t, svc.KeyService().KeyID(), token.Header["kid"])

	// Verify token contents
	parsed, err := svc.ValidateAccessTokenWithContext(context.Background(), tokenString)
	require.NoError(t, err)
	assert.Equal(t, "account-001", parsed.AccountID)
	assert.Equal(t, []string{"admin"}, parsed.Roles)
	assert.Equal(t, "session-001", parsed.SessionID)
	assert.Equal(t, "http://localhost:8080", parsed.Issuer)
	assert.NotNil(t, parsed.ExpiresAt)
	assert.NotNil(t, parsed.IssuedAt)
}

func TestValidateAccessTokenWithContext_HS256Rejected(t *testing.T) {
	svc, redis := setupTestTokenService(t)
	defer redis.Close()

	// Sign a token with the old HS256 secret key
	secret := []byte("test-secret-key-for-jwt")
	claims := &domain.AccessTokenClaims{
		AccountID: "account-hs256",
		SessionID: "session-hs256",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "http://localhost:8080",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	hs256Token, err := token.SignedString(secret)
	require.NoError(t, err)

	// Verify HS256 token is rejected by ValidateAccessTokenWithContext (only RS256 accepted)
	_, err = svc.ValidateAccessTokenWithContext(context.Background(), hs256Token)
	assert.Error(t, err)
}

func TestValidateAccessTokenWithContext_WrongKey(t *testing.T) {
	svc, redis := setupTestTokenService(t)
	defer redis.Close()

	// Sign token with a different RSA key
	otherKey, err := rsa.GenerateKey(nil, 2048)
	require.NoError(t, err)

	claims := &domain.AccessTokenClaims{
		AccountID: "account-wrong",
		SessionID: "session-wrong",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "http://localhost:8080",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "wrong-key"
	wrongToken, err := token.SignedString(otherKey)
	require.NoError(t, err)

	// Verify failure (signature mismatch)
	_, err = svc.ValidateAccessTokenWithContext(context.Background(), wrongToken)
	assert.Error(t, err)
}

func TestValidateAccessTokenWithContext_Revoked(t *testing.T) {
	svc, redis := setupTestTokenService(t)
	defer redis.Close()

	ctx := context.Background()

	claims := &domain.AccessTokenClaims{
		AccountID: "account-002",
		SessionID: "session-002",
	}

	tokenString, err := svc.GenerateAccessToken(claims)
	require.NoError(t, err)

	// Validate normal token
	parsed, err := svc.ValidateAccessTokenWithContext(ctx, tokenString)
	require.NoError(t, err)

	// Add to blacklist
	err = svc.blacklist.RevokeToken(ctx, parsed.ID, "test", parsed.ExpiresAt.Time)
	require.NoError(t, err)

	// Validate again should fail
	_, err = svc.ValidateAccessTokenWithContext(ctx, tokenString)
	assert.Error(t, err)

	// Clean up
	_ = svc.blacklist.removeFromBlacklist(ctx, parsed.ID)
}

func TestGenerateAndValidateRefreshToken(t *testing.T) {
	svc, redis := setupTestTokenService(t)
	defer redis.Close()

	ctx := context.Background()

	rt, err := svc.GenerateRefreshToken(ctx, "account-001", "client-001", "session-001", "openid profile")
	require.NoError(t, err)
	assert.NotEmpty(t, rt.Token)
	assert.Equal(t, "account-001", rt.AccountID)
	assert.Equal(t, "client-001", rt.ClientID)
	assert.Equal(t, "session-001", rt.SessionID)
	assert.True(t, rt.ExpiresAt.After(time.Now()))

	// Validate
	validated, err := svc.ValidateRefreshToken(ctx, rt.Token)
	require.NoError(t, err)
	assert.Equal(t, rt.AccountID, validated.AccountID)
	assert.Equal(t, rt.Token, validated.Token)

	// Clean up
	_ = svc.RevokeRefreshToken(ctx, rt.Token)
}

func TestRotateRefreshToken(t *testing.T) {
	svc, redis := setupTestTokenService(t)
	defer redis.Close()

	ctx := context.Background()

	// Generate initial token
	rt, err := svc.GenerateRefreshToken(ctx, "account-003", "client-003", "session-003", "openid")
	require.NoError(t, err)
	oldToken := rt.Token

	// Rotate
	newRT, err := svc.RotateRefreshToken(ctx, oldToken)
	require.NoError(t, err)
	assert.NotEqual(t, oldToken, newRT.Token)
	assert.Equal(t, "account-003", newRT.AccountID)

	// Old token should be invalid
	_, err = svc.ValidateRefreshToken(ctx, oldToken)
	assert.Error(t, err)

	// New token should be valid
	_, err = svc.ValidateRefreshToken(ctx, newRT.Token)
	assert.NoError(t, err)

	// Clean up
	_ = svc.RevokeRefreshToken(ctx, newRT.Token)
}

func TestRevokeRefreshToken(t *testing.T) {
	svc, redis := setupTestTokenService(t)
	defer redis.Close()

	ctx := context.Background()

	rt, err := svc.GenerateRefreshToken(ctx, "account-004", "", "session-004", "")
	require.NoError(t, err)

	// Revoke
	err = svc.RevokeRefreshToken(ctx, rt.Token)
	require.NoError(t, err)

	// Verify it is invalid
	_, err = svc.ValidateRefreshToken(ctx, rt.Token)
	assert.Error(t, err)
}

func TestValidateRefreshToken_NotFound(t *testing.T) {
	svc, redis := setupTestTokenService(t)
	defer redis.Close()

	ctx := context.Background()

	_, err := svc.ValidateRefreshToken(ctx, "nonexistent-token")
	assert.Error(t, err)
}

func TestKeyService(t *testing.T) {
	svc, redis := setupTestTokenService(t)
	defer redis.Close()

	keySvc := svc.KeyService()
	assert.NotNil(t, keySvc)
	assert.NotNil(t, keySvc.PrivateKey())
	assert.NotNil(t, keySvc.PublicKey())
	assert.NotEmpty(t, keySvc.KeyID())
}
