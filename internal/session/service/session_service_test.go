package service

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/session/domain"
)

func setupTestSessionService(t *testing.T) *SessionService {
	logger := zap.NewNop()
	dsn := os.Getenv("GOUNO_REDIS_DSN")
	if dsn == "" {
		dsn = "redis://localhost:6379/15"
	}

	redisClient, err := cache.NewRedisClient(dsn, 10, 5*time.Second, logger)
	if err != nil {
		t.Skip("Redis not available, skipping test:", err)
	}

	service := NewSessionService(redisClient, logger)
	service.SetSessionTTL(10 * time.Second) // short TTL for tests

	return service
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
	service := setupTestSessionService(t)
	defer service.redis.Close()

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
	service := setupTestSessionService(t)
	defer service.redis.Close()

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
	service := setupTestSessionService(t)
	defer service.redis.Close()

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
	service := setupTestSessionService(t)
	defer service.redis.Close()

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
	service := setupTestSessionService(t)
	defer service.redis.Close()

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
	service := setupTestSessionService(t)
	defer service.redis.Close()

	err := service.RevokeSession(context.Background(), "account-001", uuid.New().String())
	assert.Equal(t, ErrSessionNotFound, err)
}

func TestSessionService_ListSessionsByAccount_Empty(t *testing.T) {
	service := setupTestSessionService(t)
	defer service.redis.Close()

	sessions, err := service.ListSessionsByAccount(context.Background(), "nonexistent-account")
	require.NoError(t, err)
	assert.Len(t, sessions, 0)
}

func TestSessionService_RevokeAllForAccount_Empty(t *testing.T) {
	service := setupTestSessionService(t)
	defer service.redis.Close()

	err := service.RevokeAllForAccount(context.Background(), "nonexistent-account")
	require.NoError(t, err)
}

func TestSessionService_ErrorDefinitions(t *testing.T) {
	assert.Equal(t, "session not found", ErrSessionNotFound.Error())
	assert.Equal(t, "session expired", ErrSessionExpired.Error())
}
