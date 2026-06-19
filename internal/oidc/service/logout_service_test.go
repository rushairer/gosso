package service

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
	sessionService "github.com/rushairer/gosso/internal/session/service"
	"github.com/rushairer/gosso/internal/testutil"
	tokenService "github.com/rushairer/gosso/internal/token/service"
)

func setupTestLogoutService(t *testing.T) (*LogoutService, *tokenService.KeyService) {
	t.Helper()
	logger := zap.NewNop()
	keySvc, err := tokenService.NewKeyService("", "", false, 0, logger)
	require.NoError(t, err)

	redisClient, _ := testutil.SetupTestRedis(t)
	blacklistSvc, err := tokenService.NewBlacklistService(redisClient, logger)
	require.NoError(t, err)
	tokenSvc, err := tokenService.NewTokenService(keySvc, "https://sso.example.com", 15*time.Minute, 720*time.Hour, redisClient, blacklistSvc, nil, logger)
	require.NoError(t, err)
	logoutSvc := NewLogoutService(tokenSvc, nil, nil, "https://sso.example.com", logger)

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

	claims, err := svc.ValidateIDTokenHint(tokenString, "")
	require.NoError(t, err)
	assert.Equal(t, "account-001", claims.Subject)
	assert.Equal(t, "https://sso.example.com", claims.Issuer)
	assert.Contains(t, claims.Audience, "client-001")
}

func TestValidateIDTokenHint_ExpiredTokenAccepted(t *testing.T) {
	svc, keySvc := setupTestLogoutService(t)

	tokenString := signTestIDToken(t, keySvc, "https://sso.example.com", "account-001", []string{"client-001"}, true)

	claims, err := svc.ValidateIDTokenHint(tokenString, "")
	require.NoError(t, err)
	assert.Equal(t, "account-001", claims.Subject)
}

func TestValidateIDTokenHint_EmptyString(t *testing.T) {
	svc, _ := setupTestLogoutService(t)

	_, err := svc.ValidateIDTokenHint("", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestValidateIDTokenHint_InvalidJWT(t *testing.T) {
	svc, _ := setupTestLogoutService(t)

	_, err := svc.ValidateIDTokenHint("not-a-jwt", "")
	assert.Error(t, err)
}

func TestValidateIDTokenHint_WrongIssuer(t *testing.T) {
	svc, keySvc := setupTestLogoutService(t)

	tokenString := signTestIDToken(t, keySvc, "https://other-issuer.com", "account-001", []string{"client-001"}, false)

	_, err := svc.ValidateIDTokenHint(tokenString, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "issuer mismatch")
}

func TestValidateIDTokenHint_NoAudience(t *testing.T) {
	svc, keySvc := setupTestLogoutService(t)

	tokenString := signTestIDToken(t, keySvc, "https://sso.example.com", "account-001", nil, false)

	_, err := svc.ValidateIDTokenHint(tokenString, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no audience")
}

func TestValidateIDTokenHint_BadSignature(t *testing.T) {
	svc, _ := setupTestLogoutService(t)

	// Sign with a different key
	otherKeySvc, err := tokenService.NewKeyService("", "", false, 0, zap.NewNop())
	require.NoError(t, err)

	tokenString := signTestIDToken(t, otherKeySvc, "https://sso.example.com", "account-001", []string{"client-001"}, false)

	_, err = svc.ValidateIDTokenHint(tokenString, "")
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

	_, err = svc.ValidateIDTokenHint(tokenString, "")
	assert.Error(t, err)
}

// ──────────────────────────────────────────────
// setupTestLogoutServiceWithSession creates a LogoutService backed by a real
// SessionService (miniredis) and a TokenService with nil blacklist.
// This means RevokeAccountTokens will return ErrBlacklistNotConfigured,
// which exercises the non-fatal warning path in LogoutByAccountID.
// ──────────────────────────────────────────────
func setupTestLogoutServiceWithSession(t *testing.T) (*LogoutService, *tokenService.KeyService, *sessionService.SessionService) {
	t.Helper()
	logger := zap.NewNop()

	keySvc, err := tokenService.NewKeyService("", "", false, 0, logger)
	require.NoError(t, err)

	redisClient, _ := testutil.SetupTestRedis(t)
	blacklistSvc, err := tokenService.NewBlacklistService(redisClient, logger)
	require.NoError(t, err)
	tokenSvc, err := tokenService.NewTokenService(keySvc, "https://sso.example.com", 15*time.Minute, 720*time.Hour, redisClient, blacklistSvc, nil, logger)
	require.NoError(t, err)
	sessionSvc, err := sessionService.NewSessionServiceWithConfig(redisClient, logger, sessionService.SessionConfig{
		TokenRevoker: tokenSvc,
	})
	require.NoError(t, err)

	logoutSvc := NewLogoutService(tokenSvc, sessionSvc, nil, "https://sso.example.com", logger)
	return logoutSvc, keySvc, sessionSvc
}

func createTestSession(t *testing.T, sessionSvc *sessionService.SessionService, accountID, sessionID string) {
	t.Helper()
	ctx := context.Background()
	session := &sessionDomain.Session{
		ID:        sessionID,
		AccountID: accountID,
		Username:  "testuser",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	}
	err := sessionSvc.CreateSession(ctx, session)
	require.NoError(t, err)
}

// ──────────────────────────────────────────────
// LogoutByAccountID tests
// ──────────────────────────────────────────────

func TestLogoutByAccountID_NilSessionService(t *testing.T) {
	svc, _ := setupTestLogoutService(t) // sessionSvc is nil

	err := svc.LogoutByAccountID(context.Background(), "account-001")
	assert.ErrorIs(t, err, ErrSessionServiceNotConfigured)
}

func TestLogoutByAccountID_Success(t *testing.T) {
	svc, _, sessionSvc := setupTestLogoutServiceWithSession(t)
	ctx := context.Background()

	createTestSession(t, sessionSvc, "account-001", "session-001")

	// Verify session exists before logout
	_, err := sessionSvc.ValidateSession(ctx, "session-001")
	require.NoError(t, err)

	err = svc.LogoutByAccountID(ctx, "account-001")
	assert.NoError(t, err)

	// Verify session is gone after logout
	_, err = sessionSvc.ValidateSession(ctx, "session-001")
	assert.Error(t, err)
}

func TestLogoutByAccountID_SessionServiceError(t *testing.T) {
	logger := zap.NewNop()
	keySvc, err := tokenService.NewKeyService("", "", false, 0, logger)
	require.NoError(t, err)

	redisClient, _ := testutil.SetupTestRedis(t)
	blacklistSvc, err := tokenService.NewBlacklistService(redisClient, logger)
	require.NoError(t, err)
	tokenSvc, err := tokenService.NewTokenService(keySvc, "https://sso.example.com", 15*time.Minute, 720*time.Hour, redisClient, blacklistSvc, nil, logger)
	require.NoError(t, err)

	// Create session service WITHOUT setting tokenRevoker.
	// RevokeAllForAccount now gracefully skips token revocation and logs a warning.
	sessionSvc, err := sessionService.NewSessionService(redisClient, logger)
	require.NoError(t, err)
	logoutSvc := NewLogoutService(tokenSvc, sessionSvc, nil, "https://sso.example.com", logger)

	err = logoutSvc.LogoutByAccountID(context.Background(), "account-001")
	assert.NoError(t, err)
}

func TestLogoutByAccountID_RevokeAccountTokensNonFatal(t *testing.T) {
	svc, _, sessionSvc := setupTestLogoutServiceWithSession(t)
	ctx := context.Background()

	createTestSession(t, sessionSvc, "account-001", "session-001")

	// TokenService blacklist is nil, so RevokeAccountTokens returns
	// ErrBlacklistNotConfigured. The logout service treats this as non-fatal.
	err := svc.LogoutByAccountID(ctx, "account-001")
	assert.NoError(t, err)
}

// ──────────────────────────────────────────────
// LogoutBySessionID tests
// ──────────────────────────────────────────────

func TestLogoutBySessionID_NilSessionService(t *testing.T) {
	svc, _ := setupTestLogoutService(t) // sessionSvc is nil

	err := svc.LogoutBySessionID(context.Background(), "account-001", "session-001")
	assert.ErrorIs(t, err, ErrSessionServiceNotConfigured)
}

func TestLogoutBySessionID_Success(t *testing.T) {
	svc, _, sessionSvc := setupTestLogoutServiceWithSession(t)
	ctx := context.Background()

	createTestSession(t, sessionSvc, "account-001", "session-001")

	// Verify session exists before logout
	_, err := sessionSvc.ValidateSession(ctx, "session-001")
	require.NoError(t, err)

	err = svc.LogoutBySessionID(ctx, "account-001", "session-001")
	assert.NoError(t, err)

	// Verify session is gone after logout
	_, err = sessionSvc.ValidateSession(ctx, "session-001")
	assert.Error(t, err)
}

func TestLogoutBySessionID_SessionNotFound(t *testing.T) {
	svc, _, _ := setupTestLogoutServiceWithSession(t)

	err := svc.LogoutBySessionID(context.Background(), "account-001", "nonexistent-session")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "revoke session")
}
