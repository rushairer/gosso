package service

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/testutil"
	tokenService "github.com/rushairer/gosso/internal/token/service"
)

func setupTestLogoutService(t *testing.T) (*LogoutService, *tokenService.KeyService) {
	t.Helper()
	logger := zap.NewNop()
	keySvc, err := tokenService.NewKeyService("", "", logger)
	require.NoError(t, err)

	redisClient, _ := testutil.SetupTestRedis(t)
	tokenSvc := tokenService.NewTokenService(keySvc, "https://sso.example.com", 15*time.Minute, 720*time.Hour, redisClient, nil, logger)
	logoutSvc := NewLogoutService(tokenSvc, nil, "https://sso.example.com", logger)

	return logoutSvc, keySvc
}

func signTestIDToken(t *testing.T, keySvc *tokenService.KeyService, issuer string, accountID string, audience []string, expired bool) string {
	t.Helper()
	claims := &IDTokenClaims{}
	claims.Subject = accountID
	claims.Issuer = issuer
	claims.Audience = audience
	now := time.Now()
	claims.IssuedAt = jwt.NewNumericDate(now)
	if expired {
		claims.ExpiresAt = jwt.NewNumericDate(now.Add(-1 * time.Hour))
	} else {
		claims.ExpiresAt = jwt.NewNumericDate(now.Add(1 * time.Hour))
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keySvc.KeyID()
	tokenString, err := token.SignedString(keySvc.PrivateKey())
	require.NoError(t, err)
	return tokenString
}

func TestValidateIDTokenHint_Valid(t *testing.T) {
	svc, keySvc := setupTestLogoutService(t)

	tokenString := signTestIDToken(t, keySvc, "https://sso.example.com", "account-001", []string{"client-001"}, false)

	claims, err := svc.ValidateIDTokenHint(tokenString)
	require.NoError(t, err)
	assert.Equal(t, "account-001", claims.Subject)
	assert.Equal(t, "https://sso.example.com", claims.Issuer)
	assert.Contains(t, claims.Audience, "client-001")
}

func TestValidateIDTokenHint_ExpiredTokenAccepted(t *testing.T) {
	svc, keySvc := setupTestLogoutService(t)

	tokenString := signTestIDToken(t, keySvc, "https://sso.example.com", "account-001", []string{"client-001"}, true)

	claims, err := svc.ValidateIDTokenHint(tokenString)
	require.NoError(t, err)
	assert.Equal(t, "account-001", claims.Subject)
}

func TestValidateIDTokenHint_EmptyString(t *testing.T) {
	svc, _ := setupTestLogoutService(t)

	_, err := svc.ValidateIDTokenHint("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestValidateIDTokenHint_InvalidJWT(t *testing.T) {
	svc, _ := setupTestLogoutService(t)

	_, err := svc.ValidateIDTokenHint("not-a-jwt")
	assert.Error(t, err)
}

func TestValidateIDTokenHint_WrongIssuer(t *testing.T) {
	svc, keySvc := setupTestLogoutService(t)

	tokenString := signTestIDToken(t, keySvc, "https://other-issuer.com", "account-001", []string{"client-001"}, false)

	_, err := svc.ValidateIDTokenHint(tokenString)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "issuer mismatch")
}

func TestValidateIDTokenHint_NoAudience(t *testing.T) {
	svc, keySvc := setupTestLogoutService(t)

	tokenString := signTestIDToken(t, keySvc, "https://sso.example.com", "account-001", nil, false)

	_, err := svc.ValidateIDTokenHint(tokenString)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no audience")
}

func TestValidateIDTokenHint_BadSignature(t *testing.T) {
	svc, _ := setupTestLogoutService(t)

	// Sign with a different key
	otherKeySvc, err := tokenService.NewKeyService("", "", zap.NewNop())
	require.NoError(t, err)

	tokenString := signTestIDToken(t, otherKeySvc, "https://sso.example.com", "account-001", []string{"client-001"}, false)

	_, err = svc.ValidateIDTokenHint(tokenString)
	assert.Error(t, err)
}

func TestValidateIDTokenHint_WrongAlgorithm(t *testing.T) {
	svc, _ := setupTestLogoutService(t)

	// Sign with HMAC instead of RSA — this should be rejected
	claims := &IDTokenClaims{}
	claims.Subject = "account-001"
	claims.Issuer = "https://sso.example.com"
	claims.Audience = []string{"client-001"}
	claims.IssuedAt = jwt.NewNumericDate(time.Now())
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour))

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("hmac-secret"))
	require.NoError(t, err)

	_, err = svc.ValidateIDTokenHint(tokenString)
	assert.Error(t, err)
}
