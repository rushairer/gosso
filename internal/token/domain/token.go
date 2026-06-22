package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
	Token     string    `json:"-"`
	AccountID string    `json:"account_id"`
	ClientID  string    `json:"client_id,omitempty"`
	SessionID string    `json:"session_id,omitempty"`
	Scope     string    `json:"scope,omitempty"`
	IP        string    `json:"ip,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// Sentinel errors for RefreshToken.
var (
	ErrRefreshTokenRequired        = errors.New("refresh token: token is required")
	ErrRefreshTokenAccountRequired = errors.New("refresh token: account_id is required")
	ErrRefreshTokenExpiresRequired = errors.New("refresh token: expires_at is required")
)

// NewRefreshToken creates a new RefreshToken with validation.
func NewRefreshToken(token, accountID string, expiresAt time.Time) (*RefreshToken, error) {
	if token == "" {
		return nil, ErrRefreshTokenRequired
	}
	if accountID == "" {
		return nil, ErrRefreshTokenAccountRequired
	}
	if expiresAt.IsZero() {
		return nil, ErrRefreshTokenExpiresRequired
	}
	return &RefreshToken{
		Token:     token,
		AccountID: accountID,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}, nil
}

// HashToken computes the SHA256 hash of a token (used as Redis storage key)
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
