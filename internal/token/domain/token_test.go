package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRefreshToken_Success(t *testing.T) {
	rt, err := NewRefreshToken("token-abc", "account-123", time.Now().Add(time.Hour))
	require.NoError(t, err)
	assert.Equal(t, "token-abc", rt.Token)
	assert.Equal(t, "account-123", rt.AccountID)
	assert.False(t, rt.ExpiresAt.IsZero())
	assert.False(t, rt.CreatedAt.IsZero())
}

func TestNewRefreshToken_MissingToken(t *testing.T) {
	_, err := NewRefreshToken("", "account-123", time.Now().Add(time.Hour))
	assert.ErrorIs(t, err, ErrRefreshTokenRequired)
}

func TestNewRefreshToken_MissingAccountID(t *testing.T) {
	_, err := NewRefreshToken("token-abc", "", time.Now().Add(time.Hour))
	assert.ErrorIs(t, err, ErrRefreshTokenAccountRequired)
}

func TestNewRefreshToken_ZeroExpiry(t *testing.T) {
	_, err := NewRefreshToken("token-abc", "account-123", time.Time{})
	assert.ErrorIs(t, err, ErrRefreshTokenExpiresRequired)
}

func TestHashToken_Deterministic(t *testing.T) {
	token := "test-token-123"
	h1 := HashToken(token)
	h2 := HashToken(token)
	assert.Equal(t, h1, h2)
	assert.NotEmpty(t, h1)
	assert.Len(t, h1, 64) // SHA256 hex = 64 chars
}

func TestHashToken_DifferentInputs(t *testing.T) {
	assert.NotEqual(t, HashToken("a"), HashToken("b"))
}

func TestHashToken_Empty(t *testing.T) {
	h := HashToken("")
	assert.NotEmpty(t, h)
	assert.Len(t, h, 64)
}
