package domain

import (
	"errors"
	"time"
)

// Sentinel errors for TokenBlacklist.
var (
	ErrBlacklistJTIRequired       = errors.New("token blacklist: jti is required")
	ErrBlacklistExpiresAtRequired = errors.New("token blacklist: expires_at is required")
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

// NewTokenBlacklist creates a new TokenBlacklist with validation.
func NewTokenBlacklist(jti, reason string, expiresAt time.Time) (*TokenBlacklist, error) {
	if jti == "" {
		return nil, ErrBlacklistJTIRequired
	}
	if expiresAt.IsZero() {
		return nil, ErrBlacklistExpiresAtRequired
	}
	return &TokenBlacklist{
		JTI:       jti,
		Reason:    reason,
		RevokedAt: time.Now(),
		ExpiresAt: expiresAt,
	}, nil
}

// IsExpired checks if the token has expired (blacklist records can be cleaned up)
func (t *TokenBlacklist) IsExpired() bool {
	if t == nil {
		return true
	}
	return time.Now().After(t.ExpiresAt)
}
