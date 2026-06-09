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

	service := NewSessionService(redisClient, logger)
	service.SetSessionTTL(10 * time.Second) // short TTL for tests
	service.SetTokenRevoker(&stubTokenRevoker{})

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
	svc := NewSessionService(nil, nil)
	assert.NotNil(t, svc)
	assert.NotNil(t, svc.logger)
	assert.Equal(t, DefaultSessionTTL, svc.sessionTTL)
	assert.Equal(t, DefaultMaxSessions, svc.maxSessions)
}

func TestNewSessionService_WithLogger(t *testing.T) {
	logger := zap.NewNop()
	svc := NewSessionService(nil, logger)
	assert.NotNil(t, svc)
}

func TestSessionService_SetMaxSessions(t *testing.T) {
	svc := NewSessionService(nil, nil)
	svc.SetMaxSessions(5)
	assert.Equal(t, 5, svc.maxSessions)
}

func TestSessionService_SetSessionTTL(t *testing.T) {
	svc := NewSessionService(nil, nil)
	svc.SetSessionTTL(1 * time.Hour)
	assert.Equal(t, 1*time.Hour, svc.sessionTTL)
}

func TestSessionService_BuildSessionKey(t *testing.T) {
	svc := NewSessionService(nil, nil)
	id := uuid.New().String()
	key := svc.buildSessionKey(id)
	assert.Equal(t, SessionKeyPrefix+id, key)
}

func TestSessionService_BuildAccountSessionsKey(t *testing.T) {
	svc := NewSessionService(nil, nil)
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
	svc := NewSessionService(nil, nil)
	svc.SetMaxSessionAge(2 * time.Hour)
	assert.Equal(t, 2*time.Hour, svc.maxSessionAge)
}

func TestSessionService_SetMaxSessionAge_NoOp(t *testing.T) {
	svc := NewSessionService(nil, nil)
	original := svc.maxSessionAge
	svc.SetMaxSessionAge(0)
	assert.Equal(t, original, svc.maxSessionAge)
	svc.SetMaxSessionAge(-1 * time.Hour)
	assert.Equal(t, original, svc.maxSessionAge)
}

func TestSessionService_SetMaxSessions_Negative(t *testing.T) {
	svc := NewSessionService(nil, nil)
	original := svc.maxSessions
	svc.SetMaxSessions(-1)
	assert.Equal(t, original, svc.maxSessions)
}

func TestSessionService_SetSessionTTL_NoOp(t *testing.T) {
	svc := NewSessionService(nil, nil)
	original := svc.sessionTTL
	svc.SetSessionTTL(0)
	assert.Equal(t, original, svc.sessionTTL)
	svc.SetSessionTTL(-1 * time.Second)
	assert.Equal(t, original, svc.sessionTTL)
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

	svc := NewSessionService(redisClient, logger)
	svc.SetSessionTTL(10 * time.Second)

	ctx := context.Background()

	session := &domain.Session{
		AccountID: "account-001",
		Username:  "testuser",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	}
	err := svc.CreateSession(ctx, session)
	require.NoError(t, err)
	defer func() { _ = svc.DeleteSession(ctx, session.ID) }()

	err = svc.RevokeSession(ctx, "account-001", session.ID)
	assert.ErrorIs(t, err, ErrTokenRevokerNotConfigured)
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

	svc := NewSessionService(redisClient, logger)
	svc.SetSessionTTL(10 * time.Second)

	ctx := context.Background()
	accountID := uuid.New().String()

	session := &domain.Session{AccountID: accountID, Username: "u1", IP: "1.1.1.1", UserAgent: "a"}
	require.NoError(t, svc.CreateSession(ctx, session))
	defer func() { _ = svc.DeleteSession(ctx, session.ID) }()

	// Without a token revoker, RevokeAllForAccount should still succeed
	// and clean up session keys (token revocation is skipped with a warning).
	err := svc.RevokeAllForAccount(ctx, accountID)
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
	svc := NewSessionService(redisClient, logger)
	svc.SetSessionTTL(10 * time.Second)
	svc.SetMaxSessionAge(1 * time.Millisecond)
	svc.SetTokenRevoker(&stubTokenRevoker{})

	ctx := context.Background()
	session := &domain.Session{AccountID: "a1", Username: "u", IP: "1.1.1.1", UserAgent: "a"}
	require.NoError(t, svc.CreateSession(ctx, session))

	time.Sleep(5 * time.Millisecond)

	_, err := svc.ValidateSession(ctx, session.ID)
	assert.ErrorIs(t, err, ErrSessionExpired)
}

// ──────────────────────────────────────────────
// RefreshSession expired
// ──────────────────────────────────────────────

func TestSessionService_RefreshSession_ExpiredByMaxAge(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()

	logger := zap.NewNop()
	svc := NewSessionService(redisClient, logger)
	svc.SetSessionTTL(10 * time.Second)
	svc.SetMaxSessionAge(1 * time.Millisecond)
	svc.SetTokenRevoker(&stubTokenRevoker{})

	ctx := context.Background()
	session := &domain.Session{AccountID: "a1", Username: "u", IP: "1.1.1.1", UserAgent: "a"}
	require.NoError(t, svc.CreateSession(ctx, session))

	time.Sleep(5 * time.Millisecond)

	err := svc.RefreshSession(ctx, session.ID)
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
	assert.Equal(t, ErrSessionNotFound, err)
}

// ──────────────────────────────────────────────
// EnforceSessionLimit
// ──────────────────────────────────────────────

func TestSessionService_EnforceSessionLimit(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()
	testutil.SkipIfNoCJSON(t, redisClient)

	logger := zap.NewNop()
	svc := NewSessionService(redisClient, logger)
	svc.SetSessionTTL(10 * time.Second)
	svc.SetMaxSessions(2)
	svc.SetTokenRevoker(&stubTokenRevoker{})

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
	logger := zap.NewNop()
	svc := NewSessionService(nil, logger)
	svc.SetMaxSessions(0)
	err := svc.EnforceSessionLimit(context.Background(), "any-account")
	assert.NoError(t, err)
}

func TestSessionService_EnforceSessionLimit_NoRevoker(t *testing.T) {
	logger := zap.NewNop()
	svc := NewSessionService(nil, logger)
	svc.SetMaxSessions(5)
	err := svc.EnforceSessionLimit(context.Background(), "any-account")
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
	svc := NewSessionService(redisClient, logger)
	svc.SetSessionTTL(10 * time.Second)
	svc.SetTokenRevoker(&stubTokenRevoker{})

	ctx := context.Background()
	session := &domain.Session{AccountID: "a1", Username: "u", IP: "1.1.1.1", UserAgent: "a"}
	require.NoError(t, svc.CreateSession(ctx, session))

	// Swap to error revoker after session creation
	svc.SetTokenRevoker(&errorTokenRevoker{})

	err := svc.RevokeSession(ctx, "a1", session.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "revoke tokens for session")
}

func TestSessionService_ValidateSession_ExpiredByMaxAge_RevokerError(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()

	logger := zap.NewNop()
	svc := NewSessionService(redisClient, logger)
	svc.SetSessionTTL(10 * time.Second)
	svc.SetMaxSessionAge(1 * time.Millisecond)
	svc.SetTokenRevoker(&errorTokenRevoker{})

	ctx := context.Background()
	session := &domain.Session{AccountID: "a1", Username: "u", IP: "1.1.1.1", UserAgent: "a"}
	require.NoError(t, svc.CreateSession(ctx, session))

	time.Sleep(5 * time.Millisecond)

	// Should return ErrSessionExpired even though token revocation fails
	// (revoker error is only logged as a warning)
	_, err := svc.ValidateSession(ctx, session.ID)
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
