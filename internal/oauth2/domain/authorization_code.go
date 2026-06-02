package domain

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
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
	Used                bool      `json:"used"`
}

// IsExpired checks if the authorization code has expired
func (a *AuthorizationCode) IsExpired() bool {
	return time.Now().After(a.ExpiresAt)
}

// VerifyPKCE verifies the PKCE code_verifier
func (a *AuthorizationCode) VerifyPKCE(verifier string) bool {
	if a.CodeChallenge == "" || a.CodeChallengeMethod == "" {
		return true // No PKCE requirement, pass through
	}

	switch a.CodeChallengeMethod {
	case "S256":
		h := sha256.Sum256([]byte(verifier))
		computed := base64URLEncode(h[:])
		return computed == a.CodeChallenge
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
	ErrCodeNotFound           = fmt.Errorf("authorization code not found")
	ErrCodeExpired            = fmt.Errorf("authorization code expired")
	ErrCodeAlreadyUsed        = fmt.Errorf("authorization code already used")
	ErrCodeClientMismatch     = fmt.Errorf("authorization code client mismatch")
	ErrCodeURIMismatch        = fmt.Errorf("authorization code redirect_uri mismatch")
	ErrPKCEVerificationFailed = fmt.Errorf("PKCE verification failed")
)
