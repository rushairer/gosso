package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AccessTokenClaims JWT access token claims
type AccessTokenClaims struct {
	jwt.RegisteredClaims
	AccountID   string   `json:"account_id"`
	Username    string   `json:"username,omitempty"`
	Email       string   `json:"email,omitempty"`
	Roles       []string `json:"roles,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Scope       string   `json:"scope,omitempty"`
	ClientID    string   `json:"client_id,omitempty"`
	SessionID   string   `json:"sid,omitempty"`
}

// RefreshToken refresh token
type RefreshToken struct {
	Token     string    `json:"token"`
	AccountID string    `json:"account_id"`
	ClientID  string    `json:"client_id,omitempty"`
	SessionID string    `json:"session_id,omitempty"`
	Scope     string    `json:"scope,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

// HashToken computes the SHA256 hash of a token (used as Redis storage key)
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
