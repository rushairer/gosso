package domain

import (
	"time"

	"github.com/google/uuid"
)

// CaptchaType captcha type
type CaptchaType string

const (
	// CaptchaTypeMath mathematical formula captcha
	CaptchaTypeMath CaptchaType = "math"
	// CaptchaTypeDigit digit captcha
	CaptchaTypeDigit CaptchaType = "digit"
	// CaptchaTypeAudio audio captcha
	CaptchaTypeAudio CaptchaType = "audio"
	// CaptchaTypeImage image captcha
	CaptchaTypeImage CaptchaType = "image"
)

// Captcha captcha entity
type Captcha struct {
	ID        uuid.UUID   `json:"id"`
	Type      CaptchaType `json:"type"`
	Answer    string      `json:"answer"`
	CreatedAt time.Time   `json:"created_at"`
	ExpiresAt time.Time   `json:"expires_at"`
	// ExpiresAtUnix is the Unix timestamp of ExpiresAt for Lua script compatibility
	ExpiresAtUnix int64 `json:"expires_at_unix"`
	// Used indicates whether the captcha has been used (replay prevention)
	Used bool `json:"used"`
}

// IsExpired checks if the captcha has expired
func (c *Captcha) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}

// MarkUsed marks the captcha as used
func (c *Captcha) MarkUsed() {
	c.Used = true
}
