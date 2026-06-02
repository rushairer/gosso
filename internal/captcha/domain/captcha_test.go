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

func TestCaptcha_IsExpired_Expired(t *testing.T) {
	c := &Captcha{
		ID:        uuid.New(),
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	}
	assert.True(t, c.IsExpired())
}

func TestCaptcha_IsExpired_Valid(t *testing.T) {
	c := &Captcha{
		ID:        uuid.New(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	assert.False(t, c.IsExpired())
}

// ──────────────────────────────────────────────
// MarkUsed
// ──────────────────────────────────────────────

func TestCaptcha_MarkUsed(t *testing.T) {
	c := &Captcha{Used: false}
	assert.False(t, c.Used)
	c.MarkUsed()
	assert.True(t, c.Used)
}

// ──────────────────────────────────────────────
// CaptchaType constants
// ──────────────────────────────────────────────

func TestCaptchaType_Constants(t *testing.T) {
	assert.Equal(t, CaptchaType("math"), CaptchaTypeMath)
	assert.Equal(t, CaptchaType("digit"), CaptchaTypeDigit)
	assert.Equal(t, CaptchaType("audio"), CaptchaTypeAudio)
	assert.Equal(t, CaptchaType("image"), CaptchaTypeImage)
}
