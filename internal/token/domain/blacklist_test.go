package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTokenBlacklist_Success(t *testing.T) {
	b, err := NewTokenBlacklist("jti-123", "logout", time.Now().Add(time.Hour))
	require.NoError(t, err)
	assert.Equal(t, "jti-123", b.JTI)
	assert.Equal(t, "logout", b.Reason)
	assert.False(t, b.RevokedAt.IsZero())
	assert.False(t, b.ExpiresAt.IsZero())
}

func TestNewTokenBlacklist_MissingJTI(t *testing.T) {
	_, err := NewTokenBlacklist("", "logout", time.Now().Add(time.Hour))
	assert.ErrorIs(t, err, ErrBlacklistJTIRequired)
}

func TestNewTokenBlacklist_ZeroExpiry(t *testing.T) {
	_, err := NewTokenBlacklist("jti-123", "logout", time.Time{})
	assert.ErrorIs(t, err, ErrBlacklistExpiresAtRequired)
}

func TestTokenBlacklist_IsExpired_Expired(t *testing.T) {
	b := &TokenBlacklist{ExpiresAt: time.Now().Add(-time.Hour)}
	assert.True(t, b.IsExpired())
}

func TestTokenBlacklist_IsExpired_NotExpired(t *testing.T) {
	b := &TokenBlacklist{ExpiresAt: time.Now().Add(time.Hour)}
	assert.False(t, b.IsExpired())
}
