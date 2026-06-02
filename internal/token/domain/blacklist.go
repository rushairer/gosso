package domain

import (
	"time"
)

// TokenBlacklist token blacklist entity
type TokenBlacklist struct {
	// JTI JWT ID (unique token identifier)
	JTI string `json:"jti"`
	// Reason revocation reason
	Reason string `json:"reason"`
	// RevokedAt revocation time
	RevokedAt time.Time `json:"revoked_at"`
	// ExpiresAt original token expiration time
	ExpiresAt time.Time `json:"expires_at"`
}

// IsExpired checks if the token has expired (blacklist records can be cleaned up)
func (t *TokenBlacklist) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}
