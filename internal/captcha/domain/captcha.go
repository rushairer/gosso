package domain

import (
	"time"

	"github.com/google/uuid"
)

// CaptchaType 验证码类型
type CaptchaType string

const (
	// CaptchaTypeMath 数学算式验证码
	CaptchaTypeMath CaptchaType = "math"
	// CaptchaTypeDigit 数字验证码
	CaptchaTypeDigit CaptchaType = "digit"
	// CaptchaTypeAudio 音频验证码
	CaptchaTypeAudio CaptchaType = "audio"
	// CaptchaTypeImage 图片验证码
	CaptchaTypeImage CaptchaType = "image"
)

// Captcha 验证码实体
type Captcha struct {
	ID        uuid.UUID   `json:"id"`
	Type      CaptchaType `json:"type"`
	Answer    string      `json:"answer"`
	CreatedAt time.Time   `json:"created_at"`
	ExpiresAt time.Time   `json:"expires_at"`
	// Used 是否已被使用（防重放）
	Used bool `json:"used"`
}

// IsExpired 检查验证码是否已过期
func (c *Captcha) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}

// MarkUsed 标记验证码为已使用
func (c *Captcha) MarkUsed() {
	c.Used = true
}
