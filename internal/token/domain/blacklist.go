package domain

import (
	"time"
)

// TokenBlacklist Token 黑名单实体
type TokenBlacklist struct {
	// JTI JWT ID（Token 唯一标识）
	JTI string `json:"jti"`
	// Reason 撤销原因
	Reason string `json:"reason"`
	// RevokedAt 撤销时间
	RevokedAt time.Time `json:"revoked_at"`
	// ExpiresAt Token 原本的过期时间
	ExpiresAt time.Time `json:"expires_at"`
}

// IsExpired 检查 Token 是否已过期（黑名单记录可以清理）
func (t *TokenBlacklist) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}
