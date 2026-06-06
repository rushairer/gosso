package domain

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

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
