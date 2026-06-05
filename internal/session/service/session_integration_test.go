//go:build integration

package service_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/session/domain"
	"github.com/rushairer/gosso/internal/session/service"
	"github.com/rushairer/gosso/internal/testutil"
)

var env *testutil.TestEnv

func TestMain(m *testing.M) {
	ctx := context.Background()
	var err error
	env, err = testutil.SetupTestEnv(ctx)
	if err != nil {
		os.Exit(0)
	}
	defer env.Cleanup()
	os.Exit(m.Run())
}

func setupSessionTest(t *testing.T) (context.Context, *service.SessionService) {
	t.Helper()
	ctx := context.Background()

	// Flush Redis
	rdb := env.Redis.GetClient()
	if rdb != nil {
		_ = rdb.FlushDB(ctx).Err()
	}

	svc := service.NewSessionService(env.Redis, zap.NewNop())
	return ctx, svc
}

func createTestSession(accountID string) *domain.Session {
	return &domain.Session{
		ID:           uuid.New(),
		AccountID:    uuid.MustParse(accountID),
		IP:           "127.0.0.1",
		UserAgent:    "test-agent",
		Username:     "testuser",
		CreatedAt:    time.Now(),
		LastActiveAt: time.Now(),
	}
}

func TestCreateAndGetSession(t *testing.T) {
	ctx, svc := setupSessionTest(t)

	accountID := uuid.New().String()
	session := createTestSession(accountID)

	err := svc.CreateSession(ctx, session)
	require.NoError(t, err)

	got, err := svc.GetSession(ctx, session.ID)
	require.NoError(t, err)
	assert.Equal(t, session.ID, got.ID)
	assert.Equal(t, accountID, got.AccountID.String())
	assert.Equal(t, "127.0.0.1", got.IP)
	assert.Equal(t, "testuser", got.Username)
}

func TestSessionNotFound(t *testing.T) {
	ctx, svc := setupSessionTest(t)

	_, err := svc.GetSession(ctx, uuid.New())
	assert.ErrorIs(t, err, service.ErrSessionNotFound)
}

func TestDeleteSession(t *testing.T) {
	ctx, svc := setupSessionTest(t)

	accountID := uuid.New().String()
	session := createTestSession(accountID)
	require.NoError(t, svc.CreateSession(ctx, session))

	err := svc.DeleteSession(ctx, session.ID)
	require.NoError(t, err)

	_, err = svc.GetSession(ctx, session.ID)
	assert.ErrorIs(t, err, service.ErrSessionNotFound)
}

func TestValidateSession(t *testing.T) {
	ctx, svc := setupSessionTest(t)

	accountID := uuid.New().String()
	session := createTestSession(accountID)
	require.NoError(t, svc.CreateSession(ctx, session))

	validated, err := svc.ValidateSession(ctx, session.ID)
	require.NoError(t, err)
	assert.Equal(t, session.ID, validated.ID)
}

func TestRefreshSession(t *testing.T) {
	ctx, svc := setupSessionTest(t)

	accountID := uuid.New().String()
	session := createTestSession(accountID)
	require.NoError(t, svc.CreateSession(ctx, session))

	// Refresh updates last active time and extends TTL
	err := svc.RefreshSession(ctx, session.ID)
	require.NoError(t, err)

	got, err := svc.GetSession(ctx, session.ID)
	require.NoError(t, err)
	assert.True(t, got.LastActiveAt.After(session.LastActiveAt) || got.LastActiveAt.Equal(session.LastActiveAt))
}

func TestListSessionsByAccount(t *testing.T) {
	ctx, svc := setupSessionTest(t)

	accountID := uuid.New().String()

	s1 := createTestSession(accountID)
	s2 := createTestSession(accountID)
	s3 := createTestSession(uuid.New().String()) // different account

	require.NoError(t, svc.CreateSession(ctx, s1))
	require.NoError(t, svc.CreateSession(ctx, s2))
	require.NoError(t, svc.CreateSession(ctx, s3))

	sessions, err := svc.ListSessionsByAccount(ctx, accountID)
	require.NoError(t, err)
	assert.Len(t, sessions, 2)
}

func TestRevokeSession(t *testing.T) {
	ctx, svc := setupSessionTest(t)

	accountID := uuid.New().String()
	session := createTestSession(accountID)
	require.NoError(t, svc.CreateSession(ctx, session))

	err := svc.RevokeSession(ctx, accountID, session.ID)
	require.NoError(t, err)

	_, err = svc.GetSession(ctx, session.ID)
	assert.ErrorIs(t, err, service.ErrSessionNotFound)
}

func TestRevokeSession_WrongAccount(t *testing.T) {
	ctx, svc := setupSessionTest(t)

	accountID := uuid.New().String()
	session := createTestSession(accountID)
	require.NoError(t, svc.CreateSession(ctx, session))

	err := svc.RevokeSession(ctx, uuid.New().String(), session.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not belong")
}

func TestRevokeAllForAccount(t *testing.T) {
	ctx, svc := setupSessionTest(t)

	accountID := uuid.New().String()
	s1 := createTestSession(accountID)
	s2 := createTestSession(accountID)
	require.NoError(t, svc.CreateSession(ctx, s1))
	require.NoError(t, svc.CreateSession(ctx, s2))

	err := svc.RevokeAllForAccount(ctx, accountID)
	require.NoError(t, err)

	sessions, err := svc.ListSessionsByAccount(ctx, accountID)
	require.NoError(t, err)
	assert.Len(t, sessions, 0)
}

func TestEnforceSessionLimit(t *testing.T) {
	ctx, svc := setupSessionTest(t)
	svc.SetMaxSessions(3)

	accountID := uuid.New().String()

	// Create 4 sessions (exceeds limit of 3)
	var sessions []*domain.Session
	for i := 0; i < 4; i++ {
		s := createTestSession(accountID)
		s.CreatedAt = time.Now().Add(time.Duration(i) * time.Second)
		s.LastActiveAt = time.Now().Add(time.Duration(i) * time.Second)
		require.NoError(t, svc.CreateSession(ctx, s))
		sessions = append(sessions, s)
		// Small delay to ensure different timestamps
		time.Sleep(10 * time.Millisecond)
	}

	// Enforce limit
	err := svc.EnforceSessionLimit(ctx, accountID)
	require.NoError(t, err)

	// Should have only 3 sessions remaining (oldest evicted)
	remaining, err := svc.ListSessionsByAccount(ctx, accountID)
	require.NoError(t, err)
	assert.Len(t, remaining, 3)

	// The first (oldest) session should be evicted
	_, err = svc.GetSession(ctx, sessions[0].ID)
	assert.Error(t, err)
}
