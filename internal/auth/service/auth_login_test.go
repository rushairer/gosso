package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	accountService "github.com/rushairer/gosso/internal/account/service"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
)

// ──────────────────────────────────────────────
// safeAuditReason
// ──────────────────────────────────────────────

func TestSafeAuditReason(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"invalid credentials", ErrInvalidCredentials, "invalid_credentials"},
		{"account locked", ErrAccountLocked, "account_locked"},
		{"account inactive", accountService.ErrAccountNotActive, "account_inactive"},
		{"invalid mfa code", ErrInvalidMFACode, "invalid_mfa_code"},
		{"invalid mfa token", ErrInvalidMFAToken, "invalid_mfa_token"},
		{"invalid mfa token scope", ErrInvalidMFATokenScope, "invalid_mfa_token"},
		{"account not found", accountRepo.ErrAccountNotFound, "account_not_found"},
		{"unknown error", errors.New("something"), "internal_error"},
		{"wrapped credentials", fmt.Errorf("wrap: %w", ErrInvalidCredentials), "invalid_credentials"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, safeAuditReason(tt.err))
		})
	}
}

// ──────────────────────────────────────────────
// AuthServiceConfig (constructor-based configuration)
// ──────────────────────────────────────────────

func TestAuthServiceConfig(t *testing.T) {
	fixture := setupTestAuthService(t)

	// Default values when constructed with empty config
	assert.Equal(t, defaultLoginRateLimitWindow, fixture.svc.loginRateLimitWindow)
	assert.Equal(t, defaultLoginMaxAttempts, fixture.svc.loginMaxAttempts)
	assert.Equal(t, defaultLoginMaxAttemptsPerIP, fixture.svc.loginMaxAttemptsPerIP)
	assert.Equal(t, defaultMFAVerificationTTL, fixture.svc.mfaVerificationTTL)

	// Positive values override defaults via config
	svc := NewAuthServiceWithConfig(
		fixture.svc.db, fixture.svc.accountSvc, fixture.svc.sessionSvc,
		fixture.svc.tokenSvc, fixture.svc.credentialRepo, fixture.svc.roleRepo,
		fixture.svc.redis, fixture.svc.logger, fixture.svc.auditor,
		fixture.svc.mfaSvc, fixture.svc.passkeySvc,
		AuthServiceConfig{
			LoginRateLimitWindow:  30 * time.Minute,
			LoginMaxAttempts:      10,
			LoginMaxAttemptsPerIP: 50,
			MFAVerificationTTL:    10 * time.Minute,
		},
	)
	assert.Equal(t, 30*time.Minute, svc.loginRateLimitWindow)
	assert.Equal(t, 10, svc.loginMaxAttempts)
	assert.Equal(t, 50, svc.loginMaxAttemptsPerIP)
	assert.Equal(t, 10*time.Minute, svc.mfaVerificationTTL)

	// Zero/negative values keep defaults
	svc2 := NewAuthServiceWithConfig(
		fixture.svc.db, fixture.svc.accountSvc, fixture.svc.sessionSvc,
		fixture.svc.tokenSvc, fixture.svc.credentialRepo, fixture.svc.roleRepo,
		fixture.svc.redis, fixture.svc.logger, fixture.svc.auditor,
		fixture.svc.mfaSvc, fixture.svc.passkeySvc,
		AuthServiceConfig{
			LoginRateLimitWindow:  0,
			LoginMaxAttempts:      -1,
			LoginMaxAttemptsPerIP: 0,
			MFAVerificationTTL:    -1 * time.Minute,
		},
	)
	assert.Equal(t, defaultLoginRateLimitWindow, svc2.loginRateLimitWindow)
	assert.Equal(t, defaultLoginMaxAttempts, svc2.loginMaxAttempts)
	assert.Equal(t, defaultLoginMaxAttemptsPerIP, svc2.loginMaxAttemptsPerIP)
	assert.Equal(t, defaultMFAVerificationTTL, svc2.mfaVerificationTTL)
}

// ──────────────────────────────────────────────
// LoginByUsernamePassword
// ──────────────────────────────────────────────

func TestLoginByUsernamePassword_Success(t *testing.T) {
	fixture := setupTestAuthService(t)

	fixture.seedTestAccount("account-001", "testuser", "password123")

	// updateCredentialLastUsed -> ExecContext directly on connection pool
	fixture.sqlMock.ExpectExec("UPDATE account_credentials").
		WithArgs(sqlmock.AnyArg(), "cred-account-001").
		WillReturnResult(sqlmock.NewResult(0, 1))

	result, err := fixture.svc.LoginByUsernamePassword(context.Background(), &LoginCommand{
		Username:  "testuser",
		Password:  "password123",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.RequiresMFA)
	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.RefreshToken)
	assert.NotNil(t, result.Session)
	assert.Equal(t, "account-001", result.Account.ID)
	require.NoError(t, fixture.sqlMock.ExpectationsWereMet())
}

func TestLoginByUsernamePassword_AccountNotFound(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	result, err := fixture.svc.LoginByUsernamePassword(context.Background(), &LoginCommand{
		Username:  "unknown",
		Password:  "password123",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	})

	assert.ErrorIs(t, err, ErrInvalidCredentials)
	assert.Nil(t, result)
}

func TestLoginByUsernamePassword_WrongPassword(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	fixture.seedTestAccount("account-001", "testuser", "password123")

	result, err := fixture.svc.LoginByUsernamePassword(context.Background(), &LoginCommand{
		Username:  "testuser",
		Password:  "wrongpassword",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	})

	assert.ErrorIs(t, err, ErrInvalidCredentials)
	assert.Nil(t, result)
}

func TestLoginByUsernamePassword_InactiveAccount(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	fixture.seedTestAccount("account-001", "testuser", "password123")
	fixture.accountSvc.byID["account-001"].Status = accountDomain.AccountStatusSuspended

	result, err := fixture.svc.LoginByUsernamePassword(context.Background(), &LoginCommand{
		Username:  "testuser",
		Password:  "password123",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	})

	assert.ErrorIs(t, err, ErrInvalidCredentials)
	assert.Nil(t, result)
}

func TestLoginByUsernamePassword_RateLimited(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	fixture.seedTestAccount("account-001", "testuser", "password123")

	// Recreate the service with a low max-attempts threshold for rate-limit testing.
	fixture.svc = NewAuthServiceWithConfig(
		fixture.sqlDB,
		fixture.accountSvc,
		fixture.sessionSvc,
		fixture.tokenSvc,
		fixture.credRepo,
		fixture.roleRepo,
		fixture.redis,
		fixture.logger,
		nil, // auditor
		fixture.svc.MFAService(),
		fixture.svc.PasskeyService(),
		AuthServiceConfig{LoginMaxAttempts: 2},
	)

	// First attempt: wrong password, counter=1, not locked
	_, err := fixture.svc.LoginByUsernamePassword(context.Background(), &LoginCommand{
		Username:  "testuser",
		Password:  "wrong",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	})
	assert.ErrorIs(t, err, ErrInvalidCredentials)

	// Second attempt: counter=2 >= maxAttempts=2 -> locked
	_, err = fixture.svc.LoginByUsernamePassword(context.Background(), &LoginCommand{
		Username:  "testuser",
		Password:  "password123",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	})
	assert.ErrorIs(t, err, ErrAccountLocked)
}

func TestLoginByUsernamePassword_RedisDown_Denied(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.sqlDB.Close()

	fixture.seedTestAccount("account-001", "testuser", "password123")

	// Simulate Redis being unavailable by closing miniredis
	fixture.mr.Close()

	_, err := fixture.svc.LoginByUsernamePassword(context.Background(), &LoginCommand{
		Username:  "testuser",
		Password:  "password123",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	})
	assert.ErrorIs(t, err, ErrServiceUnavailable)
}

func TestLoginByUsernamePassword_MFARequired(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	fixture.seedTestAccount("account-001", "testuser", "password123")
	fixture.credRepo.credMap["account-001:totp"] = []*accountDomain.Credential{
		{ID: "totp-1", Type: accountDomain.CredentialTypeTOTP, Verified: true},
	}

	result, err := fixture.svc.LoginByUsernamePassword(context.Background(), &LoginCommand{
		Username:  "testuser",
		Password:  "password123",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.RequiresMFA)
	assert.NotEmpty(t, result.MFAToken)
	assert.Contains(t, result.MFATypes, "totp")
}

// ──────────────────────────────────────────────
// RefreshTokens
// ──────────────────────────────────────────────

func TestRefreshTokens_Success(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	fixture.seedTestAccount("account-001", "testuser", "password123")

	// Login to get session + refresh token
	loginResult, err := fixture.svc.LoginByUsernamePassword(context.Background(), &LoginCommand{
		Username:  "testuser",
		Password:  "password123",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	})
	require.NoError(t, err)

	refreshResult, err := fixture.svc.RefreshTokens(context.Background(), loginResult.RefreshToken)
	require.NoError(t, err)
	assert.NotEmpty(t, refreshResult.AccessToken)
	assert.NotEmpty(t, refreshResult.RefreshToken)
	assert.NotEqual(t, loginResult.RefreshToken, refreshResult.RefreshToken)
	assert.Equal(t, loginResult.Session.ID, refreshResult.SessionID)
}

func TestRefreshTokens_InvalidToken(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	_, err := fixture.svc.RefreshTokens(context.Background(), "garbage-token")
	assert.ErrorIs(t, err, ErrInvalidRefreshToken)
}

// ──────────────────────────────────────────────
// Logout
// ──────────────────────────────────────────────

func TestLogout_Success(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	fixture.seedTestAccount("account-001", "testuser", "password123")

	loginResult, err := fixture.svc.LoginByUsernamePassword(context.Background(), &LoginCommand{
		Username:  "testuser",
		Password:  "password123",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	})
	require.NoError(t, err)

	err = fixture.svc.Logout(context.Background(), "account-001", loginResult.Session.ID, "", time.Time{})
	assert.NoError(t, err)
}

func TestLogout_WithAccessToken(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	fixture.seedTestAccount("account-001", "testuser", "password123")

	loginResult, err := fixture.svc.LoginByUsernamePassword(context.Background(), &LoginCommand{
		Username:  "testuser",
		Password:  "password123",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	})
	require.NoError(t, err)

	err = fixture.svc.Logout(context.Background(), "account-001", loginResult.Session.ID, "fake-jti", time.Now().Add(15*time.Minute))
	assert.NoError(t, err)
}

// ──────────────────────────────────────────────
// ValidateMFAToken
// ──────────────────────────────────────────────

func TestValidateMFAToken_Success(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	mfaToken, err := fixture.tokenSvc.GenerateShortLivedToken(&tokenDomain.AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		AccountID: "account-001",
		Scope:     ScopeMFA,
	})
	require.NoError(t, err)

	claims, err := fixture.svc.ValidateMFAToken(context.Background(), mfaToken)
	require.NoError(t, err)
	assert.Equal(t, "account-001", claims.AccountID)
	assert.Equal(t, ScopeMFA, claims.Scope)
}

func TestValidateMFAToken_InvalidScope(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	token, err := fixture.tokenSvc.GenerateAccessToken(&tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
	})
	require.NoError(t, err)

	_, err = fixture.svc.ValidateMFAToken(context.Background(), token)
	assert.ErrorIs(t, err, ErrInvalidMFATokenScope)
}

func TestValidateMFAToken_InvalidToken(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	_, err := fixture.svc.ValidateMFAToken(context.Background(), "garbage-token")
	assert.ErrorIs(t, err, ErrInvalidMFAToken)
}

// ──────────────────────────────────────────────
// MarkPasskeyMFAVerified
// ──────────────────────────────────────────────

func TestMarkPasskeyMFAVerified(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	ctx := context.Background()
	jti := uuid.New().String()

	err := fixture.svc.MarkPasskeyMFAVerified(ctx, jti)
	require.NoError(t, err)

	val, err := fixture.redis.Get(ctx, fmt.Sprintf("webauthn:mfa_verified:%s", jti))
	require.NoError(t, err)
	assert.Equal(t, "1", val)
}

// ──────────────────────────────────────────────
// Accessors
// ──────────────────────────────────────────────

func TestMFAServiceAccessor(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	assert.NotNil(t, fixture.svc.MFAService())
}

func TestPasskeyServiceAccessor(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	assert.NotNil(t, fixture.svc.PasskeyService())
}

func TestTokenServiceAccessor(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	assert.NotNil(t, fixture.svc.TokenService())
}

// ──────────────────────────────────────────────
// ConfirmVerificationCredential
// ──────────────────────────────────────────────

func TestConfirmVerificationCredential_UnsupportedType(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	err := fixture.svc.ConfirmVerificationCredential(context.Background(), "sms", "+1234567890", "account-001")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported credential type")
}

func TestConfirmVerificationCredential_NotFound(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	fixture.sqlMock.ExpectBegin()
	fixture.sqlMock.ExpectRollback()

	err := fixture.svc.ConfirmVerificationCredential(context.Background(), "email", "nobody@example.com", "account-001")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "find credential")
}

func TestConfirmVerificationCredential_WrongAccount(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	email := "user@example.com"
	fixture.credRepo.typeAndIDCreds[string(accountDomain.CredentialTypeEmail)+":"+email] = &accountDomain.Credential{
		ID:         "cred-001",
		AccountID:  "account-001",
		Type:       accountDomain.CredentialTypeEmail,
		Identifier: &email,
		Verified:   false,
	}

	fixture.sqlMock.ExpectBegin()
	fixture.sqlMock.ExpectRollback()

	err := fixture.svc.ConfirmVerificationCredential(context.Background(), "email", email, "account-999")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not belong")
}

func TestConfirmVerificationCredential_Success(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	email := "verified@example.com"
	fixture.credRepo.typeAndIDCreds[string(accountDomain.CredentialTypeEmail)+":"+email] = &accountDomain.Credential{
		ID:         "cred-002",
		AccountID:  "account-002",
		Type:       accountDomain.CredentialTypeEmail,
		Identifier: &email,
		Verified:   false,
	}

	fixture.sqlMock.ExpectBegin()
	fixture.sqlMock.ExpectCommit()

	err := fixture.svc.ConfirmVerificationCredential(context.Background(), "email", email, "account-002")
	require.NoError(t, err)
	require.NoError(t, fixture.sqlMock.ExpectationsWereMet())

	cred := fixture.credRepo.typeAndIDCreds[string(accountDomain.CredentialTypeEmail)+":"+email]
	assert.True(t, cred.Verified)
	assert.NotNil(t, cred.VerifiedAt)
}

// ──────────────────────────────────────────────
// LoginByPasskey
// ──────────────────────────────────────────────

func TestLoginByPasskey_AccountNotFound(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	result, err := fixture.svc.LoginByPasskey(context.Background(), "nonexistent", "127.0.0.1", "test-agent")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
	assert.Nil(t, result)
}

func TestLoginByPasskey_InactiveAccount(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	fixture.seedTestAccount("account-001", "testuser", "password123")
	fixture.accountSvc.byID["account-001"].Status = accountDomain.AccountStatusSuspended

	result, err := fixture.svc.LoginByPasskey(context.Background(), "account-001", "127.0.0.1", "test-agent")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
	assert.Nil(t, result)
}

func TestLoginByPasskey_Success(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	fixture.seedTestAccount("account-001", "testuser", "password123")

	result, err := fixture.svc.LoginByPasskey(context.Background(), "account-001", "127.0.0.1", "test-agent")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.RequiresMFA)
	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.RefreshToken)
	assert.NotNil(t, result.Session)
	assert.Equal(t, "account-001", result.Account.ID)
}

func TestLoginByPasskey_MFARequired(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	fixture.seedTestAccount("account-001", "testuser", "password123")
	fixture.credRepo.credMap["account-001:totp"] = []*accountDomain.Credential{
		{ID: "totp-1", Type: accountDomain.CredentialTypeTOTP, Verified: true},
	}

	result, err := fixture.svc.LoginByPasskey(context.Background(), "account-001", "127.0.0.1", "test-agent")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.RequiresMFA)
	assert.NotEmpty(t, result.MFAToken)
	assert.Contains(t, result.MFATypes, "totp")
}

// TestLoginByPasskey_IPRateLimited was removed because IP rate limiting for passkey
// endpoints is now handled exclusively by the passkeyRateLimit middleware.
// A service-level check would double-count each attempt.

// ──────────────────────────────────────────────
// VerifyMFALogin
// ──────────────────────────────────────────────

func TestVerifyMFALogin_InvalidMFAToken(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	result, err := fixture.svc.VerifyMFALogin(context.Background(), "garbage-token", "123456", "totp", "127.0.0.1", "test-agent")
	assert.ErrorIs(t, err, ErrInvalidMFAToken)
	assert.Nil(t, result)
}

func TestVerifyMFALogin_InvalidScope(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	// Generate a regular access token (scope != "mfa")
	token, err := fixture.tokenSvc.GenerateAccessToken(&tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
	})
	require.NoError(t, err)

	result, err := fixture.svc.VerifyMFALogin(context.Background(), token, "123456", "totp", "127.0.0.1", "test-agent")
	assert.ErrorIs(t, err, ErrInvalidMFATokenScope)
	assert.Nil(t, result)
}

func TestVerifyMFALogin_UnsupportedMFAType(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	mfaToken, err := fixture.tokenSvc.GenerateShortLivedToken(&tokenDomain.AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		AccountID: "account-001",
		Scope:     ScopeMFA,
	})
	require.NoError(t, err)

	result, err := fixture.svc.VerifyMFALogin(context.Background(), mfaToken, "123456", "sms", "127.0.0.1", "test-agent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported")
	assert.Nil(t, result)
}

func TestVerifyMFALogin_PasskeyNotVerified(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	mfaToken, err := fixture.tokenSvc.GenerateShortLivedToken(&tokenDomain.AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		AccountID: "account-001",
		Scope:     ScopeMFA,
	})
	require.NoError(t, err)

	// No Redis flag set → passkey not verified
	result, err := fixture.svc.VerifyMFALogin(context.Background(), mfaToken, "", "passkey", "127.0.0.1", "test-agent")
	assert.ErrorIs(t, err, ErrPasskeyNotVerified)
	assert.Nil(t, result)
}

func TestVerifyMFALogin_Success(t *testing.T) {
	fixture := setupTestAuthService(t)

	fixture.seedTestAccount("account-001", "testuser", "password123")

	// Generate a real TOTP secret and store it as a verified credential
	secret, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "http://localhost:8080",
		AccountName: "account-001",
	})
	require.NoError(t, err)

	fixture.credRepo.credMap["account-001:totp"] = []*accountDomain.Credential{
		{ID: "totp-001", AccountID: "account-001", Type: accountDomain.CredentialTypeTOTP, Value: secret.Secret(), Verified: true},
	}

	// Generate a valid TOTP code
	code, err := totp.GenerateCode(secret.Secret(), time.Now())
	require.NoError(t, err)

	// Generate MFA token
	mfaToken, err := fixture.tokenSvc.GenerateShortLivedToken(&tokenDomain.AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		AccountID: "account-001",
		Scope:     ScopeMFA,
	})
	require.NoError(t, err)

	result, err := fixture.svc.VerifyMFALogin(context.Background(), mfaToken, code, "totp", "127.0.0.1", "test-agent")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.RequiresMFA)
	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.RefreshToken)
	assert.Equal(t, "account-001", result.Account.ID)
}

// ──────────────────────────────────────────────
// CompletePasskeyMFALogin
// ──────────────────────────────────────────────

func TestCompletePasskeyMFALogin_InvalidMFAToken(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	result, err := fixture.svc.CompletePasskeyMFALogin(context.Background(), "garbage-token", "127.0.0.1", "test-agent")
	assert.ErrorIs(t, err, ErrInvalidMFAToken)
	assert.Nil(t, result)
}

func TestCompletePasskeyMFALogin_InvalidScope(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	token, err := fixture.tokenSvc.GenerateAccessToken(&tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
	})
	require.NoError(t, err)

	result, err := fixture.svc.CompletePasskeyMFALogin(context.Background(), token, "127.0.0.1", "test-agent")
	assert.ErrorIs(t, err, ErrInvalidMFATokenScope)
	assert.Nil(t, result)
}

func TestCompletePasskeyMFALogin_PasskeyNotVerified(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	mfaToken, err := fixture.tokenSvc.GenerateShortLivedToken(&tokenDomain.AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		AccountID: "account-001",
		Scope:     ScopeMFA,
	})
	require.NoError(t, err)

	result, err := fixture.svc.CompletePasskeyMFALogin(context.Background(), mfaToken, "127.0.0.1", "test-agent")
	assert.ErrorIs(t, err, ErrPasskeyNotVerified)
	assert.Nil(t, result)
}

func TestCompletePasskeyMFALogin_AccountNotFound(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	jti := uuid.New().String()
	mfaToken, err := fixture.tokenSvc.GenerateShortLivedToken(&tokenDomain.AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		AccountID: "nonexistent",
		Scope:     ScopeMFA,
	})
	require.NoError(t, err)

	// Set passkey verified flag
	err = fixture.redis.Set(context.Background(), fmt.Sprintf("webauthn:mfa_verified:%s", jti), "1", 5*time.Minute)
	require.NoError(t, err)

	result, err := fixture.svc.CompletePasskeyMFALogin(context.Background(), mfaToken, "127.0.0.1", "test-agent")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCredentials)
	assert.Nil(t, result)
}

func TestCompletePasskeyMFALogin_Success(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	fixture.seedTestAccount("account-001", "testuser", "password123")

	jti := uuid.New().String()
	mfaToken, err := fixture.tokenSvc.GenerateShortLivedToken(&tokenDomain.AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		AccountID: "account-001",
		Scope:     ScopeMFA,
	})
	require.NoError(t, err)

	// Set passkey verified flag
	err = fixture.redis.Set(context.Background(), fmt.Sprintf("webauthn:mfa_verified:%s", jti), "1", 5*time.Minute)
	require.NoError(t, err)

	result, err := fixture.svc.CompletePasskeyMFALogin(context.Background(), mfaToken, "127.0.0.1", "test-agent")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.RequiresMFA)
	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.RefreshToken)
	assert.Equal(t, "account-001", result.Account.ID)
}

// ──────────────────────────────────────────────
// CheckMFA delegation
// ──────────────────────────────────────────────

func TestCheckMFA_NoMFA(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	fixture.seedTestAccount("account-001", "testuser", "password123")

	result, err := fixture.svc.CheckMFA(context.Background(), fixture.accountSvc.byID["account-001"])
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestCheckMFA_WithMFA(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	fixture.seedTestAccount("account-001", "testuser", "password123")
	fixture.credRepo.credMap["account-001:totp"] = []*accountDomain.Credential{
		{ID: "totp-1", Type: accountDomain.CredentialTypeTOTP, Verified: true},
	}

	result, err := fixture.svc.CheckMFA(context.Background(), fixture.accountSvc.byID["account-001"])
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.RequiresMFA)
}

// ──────────────────────────────────────────────
// ValidateSession / ListSessions delegation
// ──────────────────────────────────────────────

func TestValidateSession_Delegation(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	_, err := fixture.svc.ValidateSession(context.Background(), "nonexistent-session")
	assert.Error(t, err)
}

func TestListSessions_Delegation(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	sessions, err := fixture.svc.ListSessions(context.Background(), "account-999")
	require.NoError(t, err)
	assert.Empty(t, sessions)
}

// ──────────────────────────────────────────────
// verifyMFACode paths (via VerifyMFALogin)
// ──────────────────────────────────────────────

func TestVerifyMFALogin_PasskeySuccess(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	fixture.seedTestAccount("account-001", "testuser", "password123")

	jti := uuid.New().String()
	mfaToken, err := fixture.tokenSvc.GenerateShortLivedToken(&tokenDomain.AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		AccountID: "account-001",
		Scope:     ScopeMFA,
	})
	require.NoError(t, err)

	// Pre-set the passkey verified flag in Redis (normally set by CompleteMFALogin).
	err = fixture.redis.Set(context.Background(), fmt.Sprintf("webauthn:mfa_verified:%s", jti), "1", 5*time.Minute)
	require.NoError(t, err)

	result, err := fixture.svc.VerifyMFALogin(context.Background(), mfaToken, "", "passkey", "127.0.0.1", "test-agent")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.RequiresMFA)
	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.RefreshToken)
	assert.Equal(t, "account-001", result.Account.ID)
}

func TestVerifyMFALogin_PasskeyServiceNil(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	mfaToken, err := fixture.tokenSvc.GenerateShortLivedToken(&tokenDomain.AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		AccountID: "account-001",
		Scope:     ScopeMFA,
	})
	require.NoError(t, err)

	// Nil out the passkey service to trigger ErrPasskeyNotAvailable.
	fixture.svc.passkeySvc = nil

	result, err := fixture.svc.VerifyMFALogin(context.Background(), mfaToken, "", "passkey", "127.0.0.1", "test-agent")
	assert.ErrorIs(t, err, ErrPasskeyNotAvailable)
	assert.Nil(t, result)
}

func TestVerifyMFALogin_TOTPVerifyError(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	mfaToken, err := fixture.tokenSvc.GenerateShortLivedToken(&tokenDomain.AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		AccountID: "account-001",
		Scope:     ScopeMFA,
	})
	require.NoError(t, err)

	// Make FindByAccountAndType return an error so VerifyTOTP fails.
	fixture.credRepo.findByAccountAndTypeErr = errors.New("db connection lost")

	result, err := fixture.svc.VerifyMFALogin(context.Background(), mfaToken, "123456", "totp", "127.0.0.1", "test-agent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "totp verification error")
	assert.Nil(t, result)
}

func TestVerifyMFALogin_TOTPInvalid_BackupCodeInvalid(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	fixture.seedTestAccount("account-001", "testuser", "password123")

	// Seed TOTP credential with an invalid secret — totp.Validate returns false.
	fixture.credRepo.credMap["account-001:totp"] = []*accountDomain.Credential{
		{ID: "totp-001", AccountID: "account-001", Type: accountDomain.CredentialTypeTOTP, Value: "INVALIDBASE32SECRET!!", Verified: true},
	}
	// No backup codes in the map → VerifyBackupCode returns (false, nil).

	mfaToken, err := fixture.tokenSvc.GenerateShortLivedToken(&tokenDomain.AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		AccountID: "account-001",
		Scope:     ScopeMFA,
	})
	require.NoError(t, err)

	// VerifyBackupCode opens a transaction (Begin + Commit).
	fixture.sqlMock.ExpectBegin()
	fixture.sqlMock.ExpectCommit()

	result, err := fixture.svc.VerifyMFALogin(context.Background(), mfaToken, "000000", "totp", "127.0.0.1", "test-agent")
	assert.ErrorIs(t, err, ErrInvalidMFACode)
	assert.Nil(t, result)
	require.NoError(t, fixture.sqlMock.ExpectationsWereMet())
}

func TestVerifyMFALogin_TOTPInvalid_BackupCodeSuccess(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	fixture.seedTestAccount("account-001", "testuser", "password123")

	// Seed TOTP credential with an invalid secret — TOTP will not match.
	fixture.credRepo.credMap["account-001:totp"] = []*accountDomain.Credential{
		{ID: "totp-001", AccountID: "account-001", Type: accountDomain.CredentialTypeTOTP, Value: "INVALIDBASE32SECRET!!", Verified: true},
	}

	// Seed a valid backup code.
	knownCode := "abcdef0123456789"
	hash, err := bcrypt.GenerateFromPassword([]byte(knownCode), bcrypt.DefaultCost)
	require.NoError(t, err)
	fixture.credRepo.credMap["account-001:backup_code"] = []*accountDomain.Credential{
		{ID: "bc-001", AccountID: "account-001", Type: accountDomain.CredentialTypeBackupCode, Value: string(hash), Verified: true},
	}

	mfaToken, err := fixture.tokenSvc.GenerateShortLivedToken(&tokenDomain.AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		AccountID: "account-001",
		Scope:     ScopeMFA,
	})
	require.NoError(t, err)

	// VerifyBackupCode transaction: Begin + Commit (backup code matched, deleted).
	fixture.sqlMock.ExpectBegin()
	fixture.sqlMock.ExpectCommit()

	result, err := fixture.svc.VerifyMFALogin(context.Background(), mfaToken, knownCode, "totp", "127.0.0.1", "test-agent")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.RequiresMFA)
	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.RefreshToken)
	assert.Equal(t, "account-001", result.Account.ID)
	require.NoError(t, fixture.sqlMock.ExpectationsWereMet())
}

func TestVerifyMFALogin_TOTPInvalid_BackupCodeError(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	fixture.seedTestAccount("account-001", "testuser", "password123")

	// Seed TOTP credential with an invalid secret — VerifyTOTP returns (false, nil).
	fixture.credRepo.credMap["account-001:totp"] = []*accountDomain.Credential{
		{ID: "totp-001", AccountID: "account-001", Type: accountDomain.CredentialTypeTOTP, Value: "INVALIDBASE32SECRET!!", Verified: true},
	}

	// Inject a DB error only in the backup-code transaction path.
	fixture.credRepo.findByAccountAndTypeForUpdateErr = errors.New("lock timeout")

	mfaToken, err := fixture.tokenSvc.GenerateShortLivedToken(&tokenDomain.AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		AccountID: "account-001",
		Scope:     ScopeMFA,
	})
	require.NoError(t, err)

	// VerifyBackupCode transaction starts but rolls back due to the error.
	fixture.sqlMock.ExpectBegin()
	fixture.sqlMock.ExpectRollback()

	result, err := fixture.svc.VerifyMFALogin(context.Background(), mfaToken, "000000", "totp", "127.0.0.1", "test-agent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "backup code verification error")
	assert.Nil(t, result)
	require.NoError(t, fixture.sqlMock.ExpectationsWereMet())
}
