package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// GossoAPIResourceAudience is the canonical audience for Gosso's own
// account-security and administration APIs. OAuth resource tokens for other
// services must use the explicit RFC 8707 resource URI instead.
const GossoAPIResourceAudience = "urn:gouno:gosso-api"

// PrincipalType identifies the security principal represented by an access
// token. Keeping the principal class explicit prevents a client_credentials
// token from being confused with a human account session.
type PrincipalType string

const (
	PrincipalTypeUserSession   PrincipalType = "user_session"
	PrincipalTypeDelegatedUser PrincipalType = "delegated_user"
	PrincipalTypeClient        PrincipalType = "client"
)

// AccessTokenClaims JWT access token claims.
type AccessTokenClaims struct {
	jwt.RegisteredClaims
	AccountID     string        `json:"account_id,omitempty"`
	Username      string        `json:"username,omitempty"`
	Email         string        `json:"email,omitempty"`
	Roles         []string      `json:"roles,omitempty"`
	Permissions   []string      `json:"permissions,omitempty"`
	Scope         string        `json:"scope,omitempty"`
	ClientID      string        `json:"client_id,omitempty"`
	SessionID     string        `json:"sid,omitempty"`
	AuthTime      *int64        `json:"auth_time,omitempty"`
	AMR           []string      `json:"amr,omitempty"`
	PrincipalType PrincipalType `json:"principal_type,omitempty"`
}

// EffectivePrincipalType returns the explicit principal type or infers the
// legacy shape for rolling-deployment compatibility. Newly issued tokens always
// carry PrincipalType.
func (c *AccessTokenClaims) EffectivePrincipalType() PrincipalType {
	if c == nil {
		return ""
	}
	if c.PrincipalType != "" {
		return c.PrincipalType
	}
	if c.AccountID != "" && c.ClientID != "" {
		return PrincipalTypeDelegatedUser
	}
	if c.AccountID != "" {
		return PrincipalTypeUserSession
	}
	if c.ClientID != "" {
		return PrincipalTypeClient
	}
	return ""
}

// IsUserSessionPrincipal reports whether claims represent a first-party human
// session rather than delegated OAuth authority or a machine identity.
func (c *AccessTokenClaims) IsUserSessionPrincipal() bool {
	return c != nil && c.EffectivePrincipalType() == PrincipalTypeUserSession && c.AccountID != "" && c.SessionID != ""
}

// IsDelegatedUserPrincipal reports whether claims represent a resource owner
// acting through an OAuth client.
func (c *AccessTokenClaims) IsDelegatedUserPrincipal() bool {
	return c != nil && c.EffectivePrincipalType() == PrincipalTypeDelegatedUser && c.AccountID != "" && c.ClientID != ""
}

// IsClientPrincipal reports whether claims represent a client_credentials
// machine principal.
func (c *AccessTokenClaims) IsClientPrincipal() bool {
	return c != nil && c.EffectivePrincipalType() == PrincipalTypeClient && c.ClientID != "" && c.AccountID == "" && c.SessionID == ""
}

// HasAudience performs an exact audience membership check.
func (c *AccessTokenClaims) HasAudience(expected string) bool {
	if c == nil || expected == "" {
		return false
	}
	for _, audience := range c.Audience {
		if audience == expected {
			return true
		}
	}
	return false
}

// RefreshToken refresh token
type RefreshToken struct {
	Token     string    `json:"-"`
	AccountID string    `json:"account_id"`
	ClientID  string    `json:"client_id,omitempty"`
	SessionID string    `json:"session_id,omitempty"`
	Scope     string    `json:"scope,omitempty"`
	Resource  string    `json:"resource,omitempty"`
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
