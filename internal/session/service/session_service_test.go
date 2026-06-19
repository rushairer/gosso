package service

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/session/domain"
	"github.com/rushairer/gosso/internal/testutil"
)

func setupTestSessionService(t *testing.T) (*SessionService, func()) {
	t.Helper()
	logger := zap.NewNop()

	redisClient, mr := testutil.SetupTestRedis(t)
	cleanup := mr.Close

	service, err := NewSessionServiceWithConfig(redisClient, logger, SessionConfig{
		SessionTTL:   10 * time.Second, // short TTL for tests
		TokenRevoker: &stubTokenRevoker{},
	})
	require.NoError(t, err)

	return service, cleanup
}

// stubTokenRevoker implements TokenRevoker for testing.
type stubTokenRevoker struct{}

func (s *stubTokenRevoker) RevokeAllForSession(_ context.Context, _ string) error { return nil }

// errorTokenRevoker implements TokenRevoker for testing; always returns an error.
type errorTokenRevoker struct{}

func (e *errorTokenRevoker) RevokeAllForSession(_ context.Context, _ string) error {
	return errors.New("revoker failure")
}

// ──────────────────────────────────────────────
// Constructor and config (no Redis needed)
// ──────────────────────────────────────────────

func TestNewSessionService_NilLogger(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()

	svc, err := NewSessionService(redisClient, nil)
	require.NoError(t, err)
	assert.NotNil(t, svc)
	assert.NotNil(t, svc.logger)
	assert.Equal(t, DefaultSessionTTL, svc.sessionTTL)
	assert.Equal(t, DefaultMaxSessions, svc.maxSessions)
}

func TestNewSessionService_NilRedis(t *testing.T) {
	svc, err := NewSessionService(nil, zap.NewNop())
	require.Error(t, err)
	assert.Nil(t, svc)
	assert.Contains(t, err.Error(), "redis must not be nil")
}

func TestNewSessionService_WithLogger(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()
	logger := zap.NewNop()
	svc, err := NewSessionService(redisClient, logger)
	require.NoError(t, err)
	assert.NotNil(t, svc)
}

func TestSessionService_SetMaxSessions(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()
	svc, err := NewSessionServiceWithConfig(redisClient, zap.NewNop(), SessionConfig{
		MaxSessions: 5,
	})
	require.NoError(t, err)
	assert.Equal(t, 5, svc.maxSessions)
}

func TestSessionService_SetTokenRevoker(t *testing.T) {
	revoker := &stubTokenRevoker{}
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()
	svc, err := NewSessionServiceWithConfig(redisClient, zap.NewNop(), SessionConfig{
		TokenRevoker: revoker,
	})
	require.NoError(t, err)
	assert.Same(t, revoker, svc.tokenRevoker)
}

func TestSessionService_SetSessionTTL(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()
	svc, err := NewSessionServiceWithConfig(redisClient, zap.NewNop(), SessionConfig{
		SessionTTL: 1 * time.Hour,
	})
	require.NoError(t, err)
	assert.Equal(t, 1*time.Hour, svc.sessionTTL)
}

func TestSessionService_BuildSessionKey(t *testing.T) {
	svc := &SessionService{}
	id := uuid.New().String()
	key := svc.buildSessionKey(id)
	assert.Equal(t, SessionKeyPrefix+id, key)
}

func TestSessionService_BuildAccountSessionsKey(t *testing.T) {
	svc := &SessionService{}
	key := svc.buildAccountSessionsKey("account-001")
	assert.Equal(t, AccountSessionsPrefix+"account-001", key)
}

// ──────────────────────────────────────────────
// Redis integration tests (skipped without Redis)
// ──────────────────────────────────────────────

func TestSessionService_CreateAndGetSession(t *testing.T) {
	service, cleanup := setupTestSessionService(t)
	defer cleanup()

	ctx := context.Background()
	accountID := uuid.New().String()

	session := &domain.Session{
		AccountID: accountID,
		Username:  "testuser",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	}

	// Create session
	err := service.CreateSession(ctx, session)
	require.NoError(t, err)
	assert.NotEmpty(t, session.ID)

	// Retrieve session
	retrieved, err := service.GetSession(ctx, session.ID)
	require.NoError(t, err)
	assert.Equal(t, session.ID, retrieved.ID)
	assert.Equal(t, accountID, retrieved.AccountID)
	assert.Equal(t, "testuser", retrieved.Username)

	// Clean up
	_ = service.DeleteSession(ctx, session.ID)
}

func TestSessionService_UpdateSession(t *testing.T) {
	service, cleanup := setupTestSessionService(t)
	defer cleanup()

	ctx := context.Background()

	session := &domain.Session{
		AccountID: uuid.New().String(),
		Username:  "testuser",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	}

	// Create session
	err := service.CreateSession(ctx, session)
	require.NoError(t, err)

	// Wait briefly
	time.Sleep(100 * time.Millisecond)

	oldLastActive := session.LastActiveAt

	// Update session
	session.MFAVerified = true
	err = service.UpdateSession(ctx, session)
	require.NoError(t, err)

	// Retrieve updated session
	retrieved, err := service.GetSession(ctx, session.ID)
	require.NoError(t, err)
	assert.True(t, retrieved.MFAVerified)
	assert.True(t, retrieved.LastActiveAt.After(oldLastActive))

	// Clean up
	_ = service.DeleteSession(ctx, session.ID)
}

func TestSessionService_DeleteSession(t *testing.T) {
	service, cleanup := setupTestSessionService(t)
	defer cleanup()

	ctx := context.Background()

	session := &domain.Session{
		AccountID: uuid.New().String(),
		Username:  "testuser",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	}

	// Create session
	err := service.CreateSession(ctx, session)
	require.NoError(t, err)

	// Delete session
	err = service.DeleteSession(ctx, session.ID)
	require.NoError(t, err)

	// Retrieve should fail
	_, err = service.GetSession(ctx, session.ID)
	assert.Equal(t, ErrSessionNotFound, err)
}

func TestSessionService_ValidateSession(t *testing.T) {
	service, cleanup := setupTestSessionService(t)
	defer cleanup()

	ctx := context.Background()

	session := &domain.Session{
		AccountID: uuid.New().String(),
		Username:  "testuser",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	}

	// Create session
	err := service.CreateSession(ctx, session)
	require.NoError(t, err)

	// Validate session (should be active)
	validated, err := service.ValidateSession(ctx, session.ID)
	require.NoError(t, err)
	assert.NotNil(t, validated)

	// Clean up
	_ = service.DeleteSession(ctx, session.ID)
}

func TestSessionService_RefreshSession(t *testing.T) {
	service, cleanup := setupTestSessionService(t)
	defer cleanup()

	ctx := context.Background()

	session := &domain.Session{
		AccountID: uuid.New().String(),
		Username:  "testuser",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	}

	// Create session
	err := service.CreateSession(ctx, session)
	require.NoError(t, err)

	oldLastActive := session.LastActiveAt
	time.Sleep(100 * time.Millisecond)

	// Refresh session
	err = service.RefreshSession(ctx, session.ID)
	require.NoError(t, err)

	// Verify activity time was updated
	retrieved, err := service.GetSession(ctx, session.ID)
	require.NoError(t, err)
	assert.True(t, retrieved.LastActiveAt.After(oldLastActive))

	// Clean up
	_ = service.DeleteSession(ctx, session.ID)
}

func TestSessionService_RevokeSession_NotFound(t *testing.T) {
	service, cleanup := setupTestSessionService(t)
	defer cleanup()

	err := service.RevokeSession(context.Background(), "account-001", uuid.New().String())
	assert.Equal(t, ErrSessionNotFound, err)
}

func TestSessionService_ListSessionsByAccount_Empty(t *testing.T) {
	service, cleanup := setupTestSessionService(t)
	defer cleanup()

	sessions, err := service.ListSessionsByAccount(context.Background(), "nonexistent-account")
	require.NoError(t, err)
	assert.Len(t, sessions, 0)
}

func TestSessionService_RevokeAllForAccount_Empty(t *testing.T) {
	service, cleanup := setupTestSessionService(t)
	defer cleanup()

	err := service.RevokeAllForAccount(context.Background(), "nonexistent-account")
	require.NoError(t, err)
}

func TestSessionService_ErrorDefinitions(t *testing.T) {
	assert.Equal(t, "session not found", ErrSessionNotFound.Error())
	assert.Equal(t, "session expired", ErrSessionExpired.Error())
}

// ──────────────────────────────────────────────
// Additional setter tests
// ──────────────────────────────────────────────

func TestSessionService_SetMaxSessionAge(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()
	svc, err := NewSessionServiceWithConfig(redisClient, zap.NewNop(), SessionConfig{
		MaxSessionAge: 2 * time.Hour,
	})
	require.NoError(t, err)
	assert.Equal(t, 2*time.Hour, svc.maxSessionAge)
}

func TestSessionService_SetMaxSessionAge_NoOp(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()
	svc, err := NewSessionServiceWithConfig(redisClient, zap.NewNop(), SessionConfig{
		MaxSessionAge: 0, // zero value should keep default
	})
	require.NoError(t, err)
	assert.Equal(t, DefaultMaxSessionAge, svc.maxSessionAge)

	svc2, err := NewSessionServiceWithConfig(redisClient, zap.NewNop(), SessionConfig{
		MaxSessionAge: -1 * time.Hour, // negative should keep default
	})
	require.NoError(t, err)
	assert.Equal(t, DefaultMaxSessionAge, svc2.maxSessionAge)
}

func TestSessionService_SetMaxSessions_Negative(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()
	svc, err := NewSessionServiceWithConfig(redisClient, zap.NewNop(), SessionConfig{
		MaxSessions: -1, // negative should keep default
	})
	require.NoError(t, err)
	assert.Equal(t, DefaultMaxSessions, svc.maxSessions)
}

func TestSessionService_SetSessionTTL_NoOp(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()
	svc, err := NewSessionServiceWithConfig(redisClient, zap.NewNop(), SessionConfig{
		SessionTTL: 0, // zero value should keep default
	})
	require.NoError(t, err)
	assert.Equal(t, DefaultSessionTTL, svc.sessionTTL)

	svc2, err := NewSessionServiceWithConfig(redisClient, zap.NewNop(), SessionConfig{
		SessionTTL: -1 * time.Second, // negative should keep default
	})
	require.NoError(t, err)
	assert.Equal(t, DefaultSessionTTL, svc2.sessionTTL)
}

// ──────────────────────────────────────────────
// RevokeSession with data
// ──────────────────────────────────────────────

func TestSessionService_RevokeSession_Success(t *testing.T) {
	service, cleanup := setupTestSessionService(t)
	defer cleanup()

	ctx := context.Background()

	session := &domain.Session{
		AccountID: "account-001",
		Username:  "testuser",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	}
	err := service.CreateSession(ctx, session)
	require.NoError(t, err)

	err = service.RevokeSession(ctx, "account-001", session.ID)
	require.NoError(t, err)

	_, err = service.GetSession(ctx, session.ID)
	assert.Equal(t, ErrSessionNotFound, err)
}

func TestSessionService_RevokeSession_AccessDenied(t *testing.T) {
	service, cleanup := setupTestSessionService(t)
	defer cleanup()

	ctx := context.Background()

	session := &domain.Session{
		AccountID: "account-001",
		Username:  "testuser",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	}
	err := service.CreateSession(ctx, session)
	require.NoError(t, err)
	defer func() { _ = service.DeleteSession(ctx, session.ID) }()

	err = service.RevokeSession(ctx, "account-OTHER", session.ID)
	assert.ErrorIs(t, err, ErrSessionAccessDenied)
}

func TestSessionService_RevokeSession_NoTokenRevoker(t *testing.T) {
	logger := zap.NewNop()
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()

	svc, err := NewSessionServiceWithConfig(redisClient, logger, SessionConfig{
		SessionTTL: 10 * time.Second,
	})
	require.NoError(t, err)

	ctx := context.Background()

	session := &domain.Session{
		AccountID: "account-001",
		Username:  "testuser",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	}
	err = svc.CreateSession(ctx, session)
	require.NoError(t, err)
	defer func() { _ = svc.DeleteSession(ctx, session.ID) }()

	err = svc.RevokeSession(ctx, "account-001", session.ID)
	assert.NoError(t, err) // token revoker missing is now a warning, not an error

	// Session should still be deleted despite missing token revoker
	_, getErr := svc.GetSession(ctx, session.ID)
	assert.Error(t, getErr, "session should be deleted even without token revoker")
}

// ──────────────────────────────────────────────
// ListSessionsByAccount with data
// ──────────────────────────────────────────────

func TestSessionService_ListSessionsByAccount_WithData(t *testing.T) {
	service, cleanup := setupTestSessionService(t)
	defer cleanup()

	ctx := context.Background()
	accountID := uuid.New().String()

	s1 := &domain.Session{AccountID: accountID, Username: "u1", IP: "1.1.1.1", UserAgent: "a"}
	s2 := &domain.Session{AccountID: accountID, Username: "u1", IP: "2.2.2.2", UserAgent: "b"}
	require.NoError(t, service.CreateSession(ctx, s1))
	require.NoError(t, service.CreateSession(ctx, s2))
	defer func() {
		_ = service.DeleteSession(ctx, s1.ID)
		_ = service.DeleteSession(ctx, s2.ID)
	}()

	sessions, err := service.ListSessionsByAccount(ctx, accountID)
	require.NoError(t, err)
	assert.Len(t, sessions, 2)
}

// ──────────────────────────────────────────────
// RevokeAllForAccount with data
// ──────────────────────────────────────────────

func TestSessionService_RevokeAllForAccount_WithData(t *testing.T) {
	service, cleanup := setupTestSessionService(t)
	defer cleanup()

	ctx := context.Background()
	accountID := uuid.New().String()

	s1 := &domain.Session{AccountID: accountID, Username: "u1", IP: "1.1.1.1", UserAgent: "a"}
	s2 := &domain.Session{AccountID: accountID, Username: "u1", IP: "2.2.2.2", UserAgent: "b"}
	require.NoError(t, service.CreateSession(ctx, s1))
	require.NoError(t, service.CreateSession(ctx, s2))

	err := service.RevokeAllForAccount(ctx, accountID)
	require.NoError(t, err)

	sessions, err := service.ListSessionsByAccount(ctx, accountID)
	require.NoError(t, err)
	assert.Len(t, sessions, 0)
}

func TestSessionService_RevokeAllForAccount_NoTokenRevoker(t *testing.T) {
	logger := zap.NewNop()
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()

	svc, err := NewSessionServiceWithConfig(redisClient, logger, SessionConfig{
		SessionTTL: 10 * time.Second,
	})
	require.NoError(t, err)

	ctx := context.Background()
	accountID := uuid.New().String()

	session := &domain.Session{AccountID: accountID, Username: "u1", IP: "1.1.1.1", UserAgent: "a"}
	require.NoError(t, svc.CreateSession(ctx, session))
	defer func() { _ = svc.DeleteSession(ctx, session.ID) }()

	// Without a token revoker, RevokeAllForAccount should still succeed
	// and clean up session keys (token revocation is skipped with a warning).
	err = svc.RevokeAllForAccount(ctx, accountID)
	assert.NoError(t, err)

	// Verify sessions were cleaned up
	sessions, err := svc.ListSessionsByAccount(ctx, accountID)
	require.NoError(t, err)
	assert.Len(t, sessions, 0)
}

// ──────────────────────────────────────────────
// ValidateSession expired
// ──────────────────────────────────────────────

func TestSessionService_ValidateSession_ExpiredByMaxAge(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()

	logger := zap.NewNop()
	svc, err := NewSessionServiceWithConfig(redisClient, logger, SessionConfig{
		SessionTTL:    10 * time.Second,
		MaxSessionAge: 1 * time.Millisecond,
		TokenRevoker:  &stubTokenRevoker{},
	})
	require.NoError(t, err)

	ctx := context.Background()
	session := &domain.Session{AccountID: "a1", Username: "u", IP: "1.1.1.1", UserAgent: "a"}
	require.NoError(t, svc.CreateSession(ctx, session))

	time.Sleep(5 * time.Millisecond)

	_, err = svc.ValidateSession(ctx, session.ID)
	assert.ErrorIs(t, err, ErrSessionExpired)
}

// ──────────────────────────────────────────────
// RefreshSession expired
// ──────────────────────────────────────────────

func TestSessionService_RefreshSession_ExpiredByMaxAge(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()

	logger := zap.NewNop()
	svc, err := NewSessionServiceWithConfig(redisClient, logger, SessionConfig{
		SessionTTL:    10 * time.Second,
		MaxSessionAge: 1 * time.Millisecond,
		TokenRevoker:  &stubTokenRevoker{},
	})
	require.NoError(t, err)

	ctx := context.Background()
	session := &domain.Session{AccountID: "a1", Username: "u", IP: "1.1.1.1", UserAgent: "a"}
	require.NoError(t, svc.CreateSession(ctx, session))

	time.Sleep(5 * time.Millisecond)

	err = svc.RefreshSession(ctx, session.ID)
	assert.ErrorIs(t, err, ErrSessionExpired)
}

// ──────────────────────────────────────────────
// UpdateSession not found
// ──────────────────────────────────────────────

func TestSessionService_UpdateSession_NotFound(t *testing.T) {
	service, cleanup := setupTestSessionService(t)
	defer cleanup()

	session := &domain.Session{ID: uuid.New().String(), AccountID: "a1", Username: "u"}
	err := service.UpdateSession(context.Background(), session)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no longer exists")
}

// ──────────────────────────────────────────────
// EnforceSessionLimit
// ──────────────────────────────────────────────

func TestSessionService_EnforceSessionLimit(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()
	testutil.SkipIfNoCJSON(t, redisClient)

	logger := zap.NewNop()
	svc, err := NewSessionServiceWithConfig(redisClient, logger, SessionConfig{
		SessionTTL:   10 * time.Second,
		MaxSessions:  2,
		TokenRevoker: &stubTokenRevoker{},
	})
	require.NoError(t, err)

	ctx := context.Background()
	accountID := uuid.New().String()

	for i := 0; i < 3; i++ {
		s := &domain.Session{AccountID: accountID, Username: "u", IP: "1.1.1.1", UserAgent: "a"}
		require.NoError(t, svc.CreateSession(ctx, s))
		time.Sleep(5 * time.Millisecond)
	}

	sessions, err := svc.ListSessionsByAccount(ctx, accountID)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(sessions), 2)
}

func TestSessionService_EnforceSessionLimit_Disabled(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()
	svc, err := NewSessionServiceWithConfig(redisClient, zap.NewNop(), SessionConfig{})
	require.NoError(t, err)
	svc.maxSessions = 0 // directly disable (constructor treats 0 as "use default")
	err = svc.EnforceSessionLimit(context.Background(), "any-account")
	assert.NoError(t, err)
}

func TestSessionService_EnforceSessionLimit_NoRevoker(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()
	svc, err := NewSessionServiceWithConfig(redisClient, zap.NewNop(), SessionConfig{
		MaxSessions: 5,
	})
	require.NoError(t, err)
	err = svc.EnforceSessionLimit(context.Background(), "any-account")
	assert.ErrorIs(t, err, ErrTokenRevokerNotConfigured)
}

// ──────────────────────────────────────────────
// Error paths via closed Redis client
// ──────────────────────────────────────────────

func TestSessionService_CreateSession_ClosedRedis(t *testing.T) {
	service, cleanup := setupTestSessionService(t)
	defer cleanup()

	session := &domain.Session{
		AccountID: uuid.New().String(),
		Username:  "testuser",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	}

	// Close the underlying Redis client before creating
	require.NoError(t, service.redis.GetClient().Close())

	err := service.CreateSession(context.Background(), session)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "create session")
}

func TestSessionService_GetSession_ClosedRedis(t *testing.T) {
	service, cleanup := setupTestSessionService(t)
	defer cleanup()

	require.NoError(t, service.redis.GetClient().Close())

	_, err := service.GetSession(context.Background(), "any-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get session")
}

func TestSessionService_UpdateSession_ClosedRedis(t *testing.T) {
	service, cleanup := setupTestSessionService(t)
	defer cleanup()

	require.NoError(t, service.redis.GetClient().Close())

	session := &domain.Session{ID: uuid.New().String(), AccountID: "a1", Username: "u"}
	err := service.UpdateSession(context.Background(), session)
	assert.Error(t, err)
}

func TestSessionService_RefreshSession_ClosedRedis(t *testing.T) {
	service, cleanup := setupTestSessionService(t)
	defer cleanup()

	require.NoError(t, service.redis.GetClient().Close())

	err := service.RefreshSession(context.Background(), "any-id")
	assert.Error(t, err)
}

func TestSessionService_ListSessionsByAccount_ClosedRedis(t *testing.T) {
	service, cleanup := setupTestSessionService(t)
	defer cleanup()

	require.NoError(t, service.redis.GetClient().Close())

	_, err := service.ListSessionsByAccount(context.Background(), "any-account")
	assert.Error(t, err)
}

func TestSessionService_RevokeAllForAccount_ClosedRedis(t *testing.T) {
	service, cleanup := setupTestSessionService(t)
	defer cleanup()

	require.NoError(t, service.redis.GetClient().Close())

	err := service.RevokeAllForAccount(context.Background(), "any-account")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "revoke account sessions")
}

func TestSessionService_DeleteSession_NotFound(t *testing.T) {
	service, cleanup := setupTestSessionService(t)
	defer cleanup()

	// Deleting a nonexistent session should succeed (no-op).
	// Exercises the else-if branch where GetSession returns ErrSessionNotFound.
	err := service.DeleteSession(context.Background(), uuid.New().String())
	assert.NoError(t, err)
}

func TestSessionService_ListSessionsByAccount_StaleEntries(t *testing.T) {
	service, cleanup := setupTestSessionService(t)
	defer cleanup()

	ctx := context.Background()
	accountID := uuid.New().String()
	validID := uuid.New().String()
	staleID := uuid.New().String()

	// Manually create a valid session key in Redis (bypasses CreateSession
	// to avoid EnforceSessionLimit's cjson Lua script failing in miniredis).
	session := &domain.Session{ID: validID, AccountID: accountID, Username: "u", IP: "1.1.1.1", UserAgent: "a"}
	data, err := json.Marshal(session)
	require.NoError(t, err)
	require.NoError(t, service.redis.Set(ctx, service.buildSessionKey(validID), data, 10*time.Second))

	// Build the account index with both valid and stale entries
	indexKey := service.buildAccountSessionsKey(accountID)
	rdb := service.redis.GetClient()
	require.NoError(t, rdb.SAdd(ctx, indexKey, validID).Err())
	require.NoError(t, rdb.SAdd(ctx, indexKey, staleID).Err())

	// Verify index has 2 entries
	members, err := service.redis.SMembers(ctx, indexKey)
	require.NoError(t, err)
	require.Len(t, members, 2)

	sessions, err := service.ListSessionsByAccount(ctx, accountID)
	require.NoError(t, err)
	// Should return only the valid session; stale entry cleaned up
	require.Len(t, sessions, 1)
	assert.Equal(t, validID, sessions[0].ID)

	// Verify stale entry was removed from the index
	members, err = service.redis.SMembers(ctx, indexKey)
	require.NoError(t, err)
	assert.Len(t, members, 1)
	assert.Equal(t, validID, members[0])
}

func TestSessionService_RevokeSession_RevokerError(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()

	logger := zap.NewNop()
	svc, err := NewSessionServiceWithConfig(redisClient, logger, SessionConfig{
		SessionTTL:   10 * time.Second,
		TokenRevoker: &errorTokenRevoker{},
	})
	require.NoError(t, err)

	ctx := context.Background()
	session := &domain.Session{AccountID: "a1", Username: "u", IP: "1.1.1.1", UserAgent: "a"}
	require.NoError(t, svc.CreateSession(ctx, session))

	// Swap to error revoker after session creation

	err = svc.RevokeSession(ctx, "a1", session.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "revoke tokens for session")
}

func TestSessionService_ValidateSession_ExpiredByMaxAge_RevokerError(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()

	logger := zap.NewNop()
	svc, err := NewSessionServiceWithConfig(redisClient, logger, SessionConfig{
		SessionTTL:    10 * time.Second,
		MaxSessionAge: 1 * time.Millisecond,
		TokenRevoker:  &errorTokenRevoker{},
	})
	require.NoError(t, err)

	ctx := context.Background()
	session := &domain.Session{AccountID: "a1", Username: "u", IP: "1.1.1.1", UserAgent: "a"}
	require.NoError(t, svc.CreateSession(ctx, session))

	time.Sleep(5 * time.Millisecond)

	// Should return ErrSessionExpired even though token revocation fails
	// (revoker error is only logged as a warning)
	_, err = svc.ValidateSession(ctx, session.ID)
	assert.ErrorIs(t, err, ErrSessionExpired)
}

func TestSessionService_EnforceSessionLimit_ClosedRedis(t *testing.T) {
	service, cleanup := setupTestSessionService(t)
	defer cleanup()

	require.NoError(t, service.redis.GetClient().Close())

	err := service.EnforceSessionLimit(context.Background(), "any-account")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "evict oldest sessions")
}
