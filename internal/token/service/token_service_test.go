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
		[]byte("test-secret-key-for-jwt"),
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

	// 解析 token 验证 alg 和 kid header
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenString, &domain.AccessTokenClaims{})
	require.NoError(t, err)

	assert.Equal(t, "RS256", token.Header["alg"])
	assert.Equal(t, svc.KeyService().KeyID(), token.Header["kid"])

	// 验证 token 内容
	parsed, err := svc.ValidateAccessToken(tokenString)
	require.NoError(t, err)
	assert.Equal(t, "account-001", parsed.AccountID)
	assert.Equal(t, []string{"admin"}, parsed.Roles)
	assert.Equal(t, "session-001", parsed.SessionID)
	assert.Equal(t, "http://localhost:8080", parsed.Issuer)
	assert.NotNil(t, parsed.ExpiresAt)
	assert.NotNil(t, parsed.IssuedAt)
}

func TestValidateAccessToken_HS256Fallback(t *testing.T) {
	svc, redis := setupTestTokenService(t)
	defer redis.Close()

	// 用 HS256 旧密钥签发一个 token
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

	// 验证 HS256 token 仍可通过 ValidateAccessToken（向后兼容）
	parsed, err := svc.ValidateAccessToken(hs256Token)
	require.NoError(t, err)
	assert.Equal(t, "account-hs256", parsed.AccountID)
}

func TestValidateAccessToken_WrongKey(t *testing.T) {
	svc, redis := setupTestTokenService(t)
	defer redis.Close()

	// 用不同的 RSA 密钥签发 token
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

	// 验证失败（签名不匹配）
	_, err = svc.ValidateAccessToken(wrongToken)
	assert.Error(t, err)
}

func TestValidateAccessToken_Revoked(t *testing.T) {
	svc, redis := setupTestTokenService(t)
	defer redis.Close()

	ctx := context.Background()

	claims := &domain.AccessTokenClaims{
		AccountID: "account-002",
		SessionID: "session-002",
	}

	tokenString, err := svc.GenerateAccessToken(claims)
	require.NoError(t, err)

	// 验证正常 token
	parsed, err := svc.ValidateAccessToken(tokenString)
	require.NoError(t, err)

	// 加入黑名单
	err = svc.blacklist.RevokeToken(ctx, parsed.ID, "test", parsed.ExpiresAt.Time)
	require.NoError(t, err)

	// 再次验证应失败
	_, err = svc.ValidateAccessToken(tokenString)
	assert.Error(t, err)

	// 清理
	_ = svc.blacklist.RemoveFromBlacklist(ctx, parsed.ID)
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

	// 验证
	validated, err := svc.ValidateRefreshToken(ctx, rt.Token)
	require.NoError(t, err)
	assert.Equal(t, rt.AccountID, validated.AccountID)
	assert.Equal(t, rt.Token, validated.Token)

	// 清理
	_ = svc.RevokeRefreshToken(ctx, rt.Token)
}

func TestRotateRefreshToken(t *testing.T) {
	svc, redis := setupTestTokenService(t)
	defer redis.Close()

	ctx := context.Background()

	// 生成初始 token
	rt, err := svc.GenerateRefreshToken(ctx, "account-003", "client-003", "session-003", "openid")
	require.NoError(t, err)
	oldToken := rt.Token

	// 轮转
	newRT, err := svc.RotateRefreshToken(ctx, oldToken)
	require.NoError(t, err)
	assert.NotEqual(t, oldToken, newRT.Token)
	assert.Equal(t, "account-003", newRT.AccountID)

	// 旧 token 应失效
	_, err = svc.ValidateRefreshToken(ctx, oldToken)
	assert.Error(t, err)

	// 新 token 应有效
	_, err = svc.ValidateRefreshToken(ctx, newRT.Token)
	assert.NoError(t, err)

	// 清理
	_ = svc.RevokeRefreshToken(ctx, newRT.Token)
}

func TestRevokeRefreshToken(t *testing.T) {
	svc, redis := setupTestTokenService(t)
	defer redis.Close()

	ctx := context.Background()

	rt, err := svc.GenerateRefreshToken(ctx, "account-004", "", "session-004", "")
	require.NoError(t, err)

	// 撤销
	err = svc.RevokeRefreshToken(ctx, rt.Token)
	require.NoError(t, err)

	// 验证已失效
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
