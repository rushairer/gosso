package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/oauth2/domain"
)

func setupTestAuthCodeService(t *testing.T) *AuthCodeService {
	logger := zap.NewNop()
	dsn := "redis://localhost:6379/15"

	redisClient, err := cache.NewRedisClient(dsn, 10, 5*time.Second, logger)
	if err != nil {
		t.Skip("Redis not available, skipping test:", err)
	}

	return NewAuthCodeService(redisClient, logger, 5*time.Minute)
}

func TestGenerateCode(t *testing.T) {
	svc := setupTestAuthCodeService(t)
	defer svc.redis.Close()

	ctx := context.Background()

	code, err := svc.GenerateCode(ctx, "client-001", "account-001", "http://localhost/callback",
		[]string{"openid", "profile"}, "", "", "test-nonce")
	require.NoError(t, err)

	assert.NotEmpty(t, code.Code)
	assert.Equal(t, "client-001", code.ClientID)
	assert.Equal(t, "account-001", code.AccountID)
	assert.Equal(t, "http://localhost/callback", code.RedirectURI)
	assert.Equal(t, []string{"openid", "profile"}, code.Scopes)
	assert.Equal(t, "test-nonce", code.Nonce)
	assert.False(t, code.Used)
	assert.True(t, code.ExpiresAt.After(time.Now()))
}

func TestValidateCode_Success(t *testing.T) {
	svc := setupTestAuthCodeService(t)
	defer svc.redis.Close()

	ctx := context.Background()

	code, err := svc.GenerateCode(ctx, "client-002", "account-002", "http://localhost/callback",
		[]string{"openid"}, "", "", "")
	require.NoError(t, err)

	validated, err := svc.ValidateCode(ctx, code.Code, "client-002", "http://localhost/callback", nil)
	require.NoError(t, err)
	assert.Equal(t, "account-002", validated.AccountID)
	assert.Equal(t, []string{"openid"}, validated.Scopes)
}

func TestValidateCode_SingleUse(t *testing.T) {
	svc := setupTestAuthCodeService(t)
	defer svc.redis.Close()

	ctx := context.Background()

	code, err := svc.GenerateCode(ctx, "client-003", "account-003", "http://localhost/callback",
		[]string{"openid"}, "", "", "")
	require.NoError(t, err)

	// First use succeeds
	_, err = svc.ValidateCode(ctx, code.Code, "client-003", "http://localhost/callback", nil)
	require.NoError(t, err)

	// Second use fails (already deleted from Redis)
	_, err = svc.ValidateCode(ctx, code.Code, "client-003", "http://localhost/callback", nil)
	assert.ErrorIs(t, err, domain.ErrCodeNotFound)
}

func TestValidateCode_ClientMismatch(t *testing.T) {
	svc := setupTestAuthCodeService(t)
	defer svc.redis.Close()

	ctx := context.Background()

	code, err := svc.GenerateCode(ctx, "client-004", "account-004", "http://localhost/callback",
		[]string{"openid"}, "", "", "")
	require.NoError(t, err)

	_, err = svc.ValidateCode(ctx, code.Code, "wrong-client", "http://localhost/callback", nil)
	assert.ErrorIs(t, err, domain.ErrCodeClientMismatch)
}

func TestValidateCode_URIMismatch(t *testing.T) {
	svc := setupTestAuthCodeService(t)
	defer svc.redis.Close()

	ctx := context.Background()

	code, err := svc.GenerateCode(ctx, "client-005", "account-005", "http://localhost/callback",
		[]string{"openid"}, "", "", "")
	require.NoError(t, err)

	_, err = svc.ValidateCode(ctx, code.Code, "client-005", "http://localhost/wrong", nil)
	assert.ErrorIs(t, err, domain.ErrCodeURIMismatch)
}

func TestValidateCode_PKCE_Success(t *testing.T) {
	svc := setupTestAuthCodeService(t)
	defer svc.redis.Close()

	ctx := context.Background()

	// code_verifier = "test-verifier-123"
	// code_challenge = base64url(sha256("test-verifier-123"))
	codeChallenge := domain.HashPKCEVerifier("test-verifier-123")

	code, err := svc.GenerateCode(ctx, "client-006", "account-006", "http://localhost/callback",
		[]string{"openid"}, codeChallenge, "S256", "")
	require.NoError(t, err)

	verifier := "test-verifier-123"
	validated, err := svc.ValidateCode(ctx, code.Code, "client-006", "http://localhost/callback", &verifier)
	require.NoError(t, err)
	assert.Equal(t, "account-006", validated.AccountID)
}

func TestValidateCode_PKCE_Fail(t *testing.T) {
	svc := setupTestAuthCodeService(t)
	defer svc.redis.Close()

	ctx := context.Background()

	codeChallenge := domain.HashPKCEVerifier("correct-verifier")

	code, err := svc.GenerateCode(ctx, "client-007", "account-007", "http://localhost/callback",
		[]string{"openid"}, codeChallenge, "S256", "")
	require.NoError(t, err)

	wrongVerifier := "wrong-verifier"
	_, err = svc.ValidateCode(ctx, code.Code, "client-007", "http://localhost/callback", &wrongVerifier)
	assert.ErrorIs(t, err, domain.ErrPKCEVerificationFailed)
}
