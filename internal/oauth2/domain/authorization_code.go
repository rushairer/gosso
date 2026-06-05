package domain

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"time"
)

// AuthorizationCode OAuth2 authorization code
type AuthorizationCode struct {
	Code                string    `json:"code"`
	ClientID            string    `json:"client_id"`
	AccountID           string    `json:"account_id"`
	RedirectURI         string    `json:"redirect_uri"`
	Scopes              []string  `json:"scopes"`
	CodeChallenge       string    `json:"code_challenge,omitempty"`
	CodeChallengeMethod string    `json:"code_challenge_method,omitempty"`
	Nonce               string    `json:"nonce,omitempty"`
	ExpiresAt           time.Time `json:"expires_at"`
	AuthTime            time.Time `json:"auth_time"` // When the user authenticated (consent time)
}

// IsExpired checks if the authorization code has expired
func (a *AuthorizationCode) IsExpired() bool {
	return time.Now().After(a.ExpiresAt)
}

// VerifyPKCE verifies the PKCE code_verifier
func (a *AuthorizationCode) VerifyPKCE(verifier string) bool {
	if a.CodeChallenge == "" {
		return true // No PKCE requirement, pass through
	}

	// RFC 7636 §4.1: code_verifier must be 43-128 characters
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}

	switch a.CodeChallengeMethod {
	case "S256":
		h := sha256.Sum256([]byte(verifier))
		computed := base64URLEncode(h[:])
		return subtle.ConstantTimeCompare([]byte(computed), []byte(a.CodeChallenge)) == 1
	default:
		return false
	}
}

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// HashPKCEVerifier computes the PKCE code_challenge (S256 method)
func HashPKCEVerifier(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64URLEncode(h[:])
}

// Error definitions
var (
	ErrCodeNotFound           = errors.New("authorization code not found")
	ErrCodeExpired            = errors.New("authorization code expired")
	ErrCodeClientMismatch     = errors.New("authorization code client mismatch")
	ErrCodeURIMismatch        = errors.New("authorization code redirect_uri mismatch")
	ErrPKCEVerificationFailed = errors.New("PKCE verification failed")
)
