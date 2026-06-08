package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTokenBlacklist_IsExpired_Expired(t *testing.T) {
	b := &TokenBlacklist{ExpiresAt: time.Now().Add(-time.Hour)}
	assert.True(t, b.IsExpired())
}

func TestTokenBlacklist_IsExpired_NotExpired(t *testing.T) {
	b := &TokenBlacklist{ExpiresAt: time.Now().Add(time.Hour)}
	assert.False(t, b.IsExpired())
}
