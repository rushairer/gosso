//go:build integration

package service_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	accountModule "github.com/rushairer/gosso/internal/account"
	auditService "github.com/rushairer/gosso/internal/audit/service"
	authModule "github.com/rushairer/gosso/internal/auth"
	"github.com/rushairer/gosso/internal/auth/service"
	"github.com/rushairer/gosso/internal/testutil"
	tokenService "github.com/rushairer/gosso/internal/token/service"
)

var env *testutil.TestEnv

func TestMain(m *testing.M) {
	ctx := context.Background()
	var err error
	env, err = testutil.SetupTestEnv(ctx)
	if err != nil {
		// Fail if infrastructure is not available — do not silently pass
		fmt.Fprintf(os.Stderr, "Test infrastructure unavailable: %v\n", err)
		os.Exit(1)
	}
	defer env.Cleanup()

	os.Exit(m.Run())
}

func setupAuthTest(t *testing.T) (context.Context, *testutil.TestEnv) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, env.TruncateAll(ctx))
	return ctx, env
}

func initAuthService(t *testing.T, e *testutil.TestEnv) *service.AuthService {
	t.Helper()
	ctx := context.Background()
	auditor := auditService.NewAuditor(ctx, e.DB, nil, e.Logger)
	accountMod := accountModule.InitializeAccountModule(e.DB, auditor, e.Logger)
	keySvc, err := tokenService.NewKeyService("", "test-key", false, 0, e.Logger)
	require.NoError(t, err)
	blacklistSvc, err := tokenService.NewBlacklistService(e.Redis, e.Logger)
	require.NoError(t, err)
	tokenSvc, err := tokenService.NewTokenService(keySvc, "http://localhost:8080", 15*time.Minute, 720*time.Hour, e.Redis, blacklistSvc, nil, e.Logger)
	require.NoError(t, err)
	authMod, err := authModule.InitializeAuthModule(authModule.AuthModuleConfig{
		DB:                    e.DB,
		Redis:                 e.Redis,
		Logger:                e.Logger,
		AuthConfig:            e.Config.AuthConfig,
		SMTPConfig:            e.Config.SMTPConfig,
		AccountSvc:            accountMod.Service,
		Providers:             nil,
		KeySvc:                keySvc,
		BaseURL:               "",
		Auditor:               auditor,
		TokenSvc:              tokenSvc,
		CredentialRepo:        accountMod.CredentialRepo,
		AccountRepo:           accountMod.AccountRepo,
		RoleRepo:              accountMod.RoleRepo,
		FederatedIdentityRepo: accountMod.FederatedIdentityRepo,
	})
	require.NoError(t, err)
	return authMod.AuthService
}

func TestLoginByUsernamePassword_Success(t *testing.T) {
	ctx, e := setupAuthTest(t)

	accountID, err := e.SeedAccount(ctx, "testuser", "test@example.com", "password123")
	require.NoError(t, err)
	assert.NotEmpty(t, accountID)

	authSvc := initAuthService(t, e)

	result, err := authSvc.LoginByUsernamePassword(ctx, &service.LoginCommand{
		Username:  "testuser",
		Password:  "password123",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.RefreshToken)
	assert.NotNil(t, result.Session)
	assert.False(t, result.RequiresMFA)
	assert.Equal(t, accountID, result.Account.ID)
}

func TestLoginByUsernamePassword_WrongPassword(t *testing.T) {
	ctx, e := setupAuthTest(t)

	_, err := e.SeedAccount(ctx, "testuser", "test@example.com", "password123")
	require.NoError(t, err)

	authSvc := initAuthService(t, e)

	result, err := authSvc.LoginByUsernamePassword(ctx, &service.LoginCommand{
		Username:  "testuser",
		Password:  "wrongpassword",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	})
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "invalid credentials")
}

func TestLoginByUsernamePassword_AccountNotFound(t *testing.T) {
	ctx, e := setupAuthTest(t)

	authSvc := initAuthService(t, e)

	result, err := authSvc.LoginByUsernamePassword(ctx, &service.LoginCommand{
		Username:  "nonexistent",
		Password:  "password123",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	})
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "invalid credentials")
}

func TestLoginAndRefresh(t *testing.T) {
	ctx, e := setupAuthTest(t)

	_, err := e.SeedAccount(ctx, "testuser", "test@example.com", "password123")
	require.NoError(t, err)

	authSvc := initAuthService(t, e)

	loginResult, err := authSvc.LoginByUsernamePassword(ctx, &service.LoginCommand{
		Username:  "testuser",
		Password:  "password123",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	})
	require.NoError(t, err)

	// JWT iat has second-precision; ensure a new token is generated
	time.Sleep(1100 * time.Millisecond)

	refreshResult, err := authSvc.RefreshTokens(ctx, loginResult.RefreshToken)
	require.NoError(t, err)
	assert.NotEmpty(t, refreshResult.AccessToken)
	assert.NotEmpty(t, refreshResult.RefreshToken)
	assert.NotEqual(t, loginResult.AccessToken, refreshResult.AccessToken)
}

func TestLoginAndLogout(t *testing.T) {
	ctx, e := setupAuthTest(t)

	_, err := e.SeedAccount(ctx, "testuser", "test@example.com", "password123")
	require.NoError(t, err)

	authSvc := initAuthService(t, e)

	loginResult, err := authSvc.LoginByUsernamePassword(ctx, &service.LoginCommand{
		Username:  "testuser",
		Password:  "password123",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	})
	require.NoError(t, err)

	session, err := authSvc.ValidateSession(ctx, loginResult.Session.ID)
	require.NoError(t, err)
	assert.NotNil(t, session)

	err = authSvc.Logout(ctx, loginResult.Account.ID, loginResult.Session.ID, "", loginResult.Session.CreatedAt)
	require.NoError(t, err)

	_, err = authSvc.ValidateSession(ctx, loginResult.Session.ID)
	assert.Error(t, err)
}

func TestLoginRateLimiting(t *testing.T) {
	ctx, e := setupAuthTest(t)

	_, err := e.SeedAccount(ctx, "testuser", "test@example.com", "password123")
	require.NoError(t, err)

	authSvc := initAuthService(t, e)

	for i := 0; i < 5; i++ {
		_, _ = authSvc.LoginByUsernamePassword(ctx, &service.LoginCommand{
			Username:  "testuser",
			Password:  "wrongpassword",
			IP:        "127.0.0.1",
			UserAgent: "test-agent",
		})
	}

	result, err := authSvc.LoginByUsernamePassword(ctx, &service.LoginCommand{
		Username:  "testuser",
		Password:  "password123",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	})
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "locked")
}

func TestSessionListAndRevoke(t *testing.T) {
	ctx, e := setupAuthTest(t)

	accountID, err := e.SeedAccount(ctx, "testuser", "test@example.com", "password123")
	require.NoError(t, err)

	authSvc := initAuthService(t, e)

	login1, err := authSvc.LoginByUsernamePassword(ctx, &service.LoginCommand{
		Username: "testuser", Password: "password123",
		IP: "127.0.0.1", UserAgent: "agent-1",
	})
	require.NoError(t, err)

	login2, err := authSvc.LoginByUsernamePassword(ctx, &service.LoginCommand{
		Username: "testuser", Password: "password123",
		IP: "127.0.0.2", UserAgent: "agent-2",
	})
	require.NoError(t, err)

	sessions, err := authSvc.ListSessions(ctx, accountID)
	require.NoError(t, err)
	assert.Len(t, sessions, 2)

	err = authSvc.RevokeSession(ctx, accountID, login1.Session.ID)
	require.NoError(t, err)

	sessions, err = authSvc.ListSessions(ctx, accountID)
	require.NoError(t, err)
	assert.Len(t, sessions, 1)
	assert.Equal(t, login2.Session.ID, sessions[0].ID)
}
