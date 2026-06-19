package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountService "github.com/rushairer/gosso/internal/account/service"
	"github.com/rushairer/gosso/internal/audit"
)

// mockTokenRevoker implements sessionService.TokenRevoker for testing.
type mockTokenRevoker struct {
	revoked []string
}

func (m *mockTokenRevoker) RevokeAllForSession(_ context.Context, sessionID string) error {
	m.revoked = append(m.revoked, sessionID)
	return nil
}

// ──────────────────────────────────────────────
// RevokeSession
// ──────────────────────────────────────────────

func TestRevokeSession_Success(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	revoker := &mockTokenRevoker{}
	fixture.sessionSvc.SetTokenRevoker(revoker)

	fixture.seedTestAccount("account-001", "testuser", "password123")
	fixture.sqlMock.ExpectBegin()
	fixture.sqlMock.ExpectCommit()

	loginResult, err := fixture.svc.LoginByUsernamePassword(context.Background(), &LoginCommand{
		Username: "testuser", Password: "password123",
		IP: "127.0.0.1", UserAgent: "test-agent",
	})
	require.NoError(t, err)
	require.NoError(t, fixture.sqlMock.ExpectationsWereMet())

	err = fixture.svc.RevokeSession(context.Background(), "account-001", loginResult.Session.ID)
	assert.NoError(t, err)
	assert.Contains(t, revoker.revoked, loginResult.Session.ID)

	// Session should no longer be valid
	_, err = fixture.svc.ValidateSession(context.Background(), loginResult.Session.ID)
	assert.Error(t, err)
}

func TestRevokeSession_SessionNotFound(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	revoker := &mockTokenRevoker{}
	fixture.sessionSvc.SetTokenRevoker(revoker)

	err := fixture.svc.RevokeSession(context.Background(), "account-001", "nonexistent-session")
	assert.Error(t, err)
	assert.Empty(t, revoker.revoked, "token revoker should not be called for missing session")
}

// ──────────────────────────────────────────────
// CreateSessionAndTokens (public wrapper)
// ──────────────────────────────────────────────

func TestCreateSessionAndTokens_Success(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	acct, _ := accountDomain.NewAccount("socialuser")
	acct.ID = "account-social"

	session, accessToken, refreshToken, err := fixture.svc.CreateSessionAndTokens(
		context.Background(), acct, "127.0.0.1", "test-agent",
	)
	require.NoError(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, "account-social", session.AccountID)
	assert.NotEmpty(t, accessToken)
	assert.NotNil(t, refreshToken)
	assert.Equal(t, session.ID, refreshToken.SessionID)
}

// ──────────────────────────────────────────────
// RefreshTokens — edge cases
// ──────────────────────────────────────────────

func TestRefreshTokens_IPMismatch(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	fixture.seedTestAccount("account-001", "testuser", "password123")
	fixture.sqlMock.ExpectBegin()
	fixture.sqlMock.ExpectCommit()

	// Login with IP "10.0.0.1" in context (captured by GenerateRefreshToken).
	loginCtx := audit.SetMetadata(context.Background(), "10.0.0.1", "test-agent", "")
	loginResult, err := fixture.svc.LoginByUsernamePassword(loginCtx, &LoginCommand{
		Username: "testuser", Password: "password123",
		IP: "10.0.0.1", UserAgent: "test-agent",
	})
	require.NoError(t, err)
	require.NoError(t, fixture.sqlMock.ExpectationsWereMet())

	// Refresh from a different IP — should be rejected.
	refreshCtx := audit.SetMetadata(context.Background(), "10.0.0.2", "test-agent", "")
	_, err = fixture.svc.RefreshTokens(refreshCtx, loginResult.RefreshToken)
	assert.ErrorIs(t, err, ErrInvalidRefreshToken)
}

func TestRefreshTokens_SessionInvalid(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	fixture.seedTestAccount("account-001", "testuser", "password123")
	fixture.sqlMock.ExpectBegin()
	fixture.sqlMock.ExpectCommit()

	loginResult, err := fixture.svc.LoginByUsernamePassword(context.Background(), &LoginCommand{
		Username: "testuser", Password: "password123",
		IP: "127.0.0.1", UserAgent: "test-agent",
	})
	require.NoError(t, err)
	require.NoError(t, fixture.sqlMock.ExpectationsWereMet())

	// Delete the session from Redis to simulate session invalidation.
	err = fixture.sessionSvc.DeleteSession(context.Background(), loginResult.Session.ID)
	require.NoError(t, err)

	_, err = fixture.svc.RefreshTokens(context.Background(), loginResult.RefreshToken)
	assert.ErrorIs(t, err, ErrSessionInvalid)
}

func TestRefreshTokens_AccountInactive(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	fixture.seedTestAccount("account-001", "testuser", "password123")
	fixture.sqlMock.ExpectBegin()
	fixture.sqlMock.ExpectCommit()

	loginResult, err := fixture.svc.LoginByUsernamePassword(context.Background(), &LoginCommand{
		Username: "testuser", Password: "password123",
		IP: "127.0.0.1", UserAgent: "test-agent",
	})
	require.NoError(t, err)
	require.NoError(t, fixture.sqlMock.ExpectationsWereMet())

	// Suspend the account after login.
	fixture.accountSvc.byID["account-001"].Status = accountDomain.AccountStatusSuspended

	_, err = fixture.svc.RefreshTokens(context.Background(), loginResult.RefreshToken)
	assert.ErrorIs(t, err, accountService.ErrAccountNotActive)
}

// ──────────────────────────────────────────────
// buildTokenClaims — edge cases
// ──────────────────────────────────────────────

func TestBuildTokenClaims_NoRoles(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	claims, err := fixture.svc.buildTokenClaims(context.Background(), "account-001", "session-001")
	require.NoError(t, err)
	assert.Equal(t, "account-001", claims.AccountID)
	assert.Equal(t, "session-001", claims.SessionID)
	assert.Empty(t, claims.Roles)
	assert.Empty(t, claims.Permissions)
}

func TestBuildTokenClaims_MultiplePermissions(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	fixture.roleRepo.roles["account-001"] = []*accountDomain.Role{
		{
			ID:          "role-1",
			Name:        "editor",
			Permissions: []string{"read", "write"},
		},
		{
			ID:          "role-2",
			Name:        "moderator",
			Permissions: []string{"moderate", "delete"},
		},
	}

	claims, err := fixture.svc.buildTokenClaims(context.Background(), "account-001", "session-001")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"editor", "moderator"}, claims.Roles)
	assert.ElementsMatch(t, []string{"read", "write", "moderate", "delete"}, claims.Permissions)
}

func TestBuildTokenClaims_DedupPermissions(t *testing.T) {
	fixture := setupTestAuthService(t)
	defer fixture.mr.Close()
	defer fixture.sqlDB.Close()

	fixture.roleRepo.roles["account-001"] = []*accountDomain.Role{
		{
			ID:          "role-1",
			Name:        "editor",
			Permissions: []string{"read", "write"},
		},
		{
			ID:          "role-2",
			Name:        "admin",
			Permissions: []string{"read", "delete"},
		},
	}

	claims, err := fixture.svc.buildTokenClaims(context.Background(), "account-001", "session-001")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"editor", "admin"}, claims.Roles)
	// "read" appears in both roles but should be deduplicated.
	assert.ElementsMatch(t, []string{"read", "write", "delete"}, claims.Permissions)
}
