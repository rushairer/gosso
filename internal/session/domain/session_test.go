package domain

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ──────────────────────────────────────────────
// NewSession
// ──────────────────────────────────────────────

func TestNewSession_Success(t *testing.T) {
	s, err := NewSession("account-001", "testuser", "127.0.0.1", "test-agent", true)

	require.NoError(t, err)
	require.NotNil(t, s)

	assert.NotEmpty(t, s.ID)
	assert.Equal(t, "account-001", s.AccountID)
	assert.Equal(t, "testuser", s.Username)
	assert.Equal(t, "127.0.0.1", s.IP)
	assert.Equal(t, "test-agent", s.UserAgent)
	assert.True(t, s.MFAVerified)
	assert.False(t, s.CreatedAt.IsZero())
	assert.False(t, s.LastActiveAt.IsZero())
	assert.Equal(t, s.CreatedAt, s.LastActiveAt)
	assert.NotNil(t, s.Metadata)
}

func TestNewSession_MFAFalse(t *testing.T) {
	s, err := NewSession("account-002", "user2", "10.0.0.1", "curl", false)

	require.NoError(t, err)
	require.NotNil(t, s)
	assert.False(t, s.MFAVerified)
}

func TestNewSession_EmptyAccountID(t *testing.T) {
	s, err := NewSession("", "testuser", "127.0.0.1", "agent", false)

	assert.Error(t, err)
	assert.Nil(t, s)
	assert.ErrorIs(t, err, ErrSessionAccountIDRequired)
}

func TestNewSession_UniqueIDs(t *testing.T) {
	s1, err := NewSession("account-001", "u1", "127.0.0.1", "agent", false)
	require.NoError(t, err)
	s2, err := NewSession("account-001", "u1", "127.0.0.1", "agent", false)
	require.NoError(t, err)

	assert.NotEqual(t, s1.ID, s2.ID, "each session should have a unique ID")
}

// ──────────────────────────────────────────────
// IsExpired
// ──────────────────────────────────────────────

func TestSession_IsExpired_Expired(t *testing.T) {
	s := &Session{
		ID:           uuid.New().String(),
		LastActiveAt: time.Now().Add(-2 * time.Hour),
	}
	assert.True(t, s.IsExpired(1*time.Hour))
}

func TestSession_IsExpired_Active(t *testing.T) {
	s := &Session{
		ID:           uuid.New().String(),
		LastActiveAt: time.Now().Add(-5 * time.Minute),
	}
	assert.False(t, s.IsExpired(1*time.Hour))
}

func TestSession_IsExpired_Exact(t *testing.T) {
	s := &Session{
		ID:           uuid.New().String(),
		LastActiveAt: time.Now().Add(-1*time.Hour - 1*time.Second),
	}
	assert.True(t, s.IsExpired(1*time.Hour))
}

func TestSession_IsExpired_NilReceiver(t *testing.T) {
	var s *Session
	assert.True(t, s.IsExpired(1*time.Hour), "nil session should be expired")
}

func TestSession_IsExpired_ZeroTTL(t *testing.T) {
	s := &Session{
		ID:           uuid.New().String(),
		LastActiveAt: time.Now().Add(-1 * time.Millisecond),
	}
	// With a zero TTL, any session with LastActiveAt in the past is expired
	assert.True(t, s.IsExpired(0))
}

// ──────────────────────────────────────────────
// UpdateActivity
// ──────────────────────────────────────────────

func TestSession_UpdateActivity(t *testing.T) {
	s := &Session{
		LastActiveAt: time.Now().Add(-1 * time.Hour),
	}
	before := time.Now()
	s.UpdateActivity()
	assert.True(t, s.LastActiveAt.After(before) || s.LastActiveAt.Equal(before))
}

func TestSession_UpdateActivity_NilReceiver(t *testing.T) {
	var s *Session
	// Should not panic on nil receiver
	assert.NotPanics(t, func() {
		s.UpdateActivity()
	})
}
