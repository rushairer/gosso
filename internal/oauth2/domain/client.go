package domain

import (
	"crypto/subtle"
	"fmt"
	"slices"
	"time"
)

// OAuth2Client OAuth2 client entity
type OAuth2Client struct {
	ID                     string         `json:"id"`
	AccountID              string         `json:"account_id"`
	ClientID               string         `json:"client_id"`
	ClientSecretHash       string         `json:"-"` // Only has value for confidential clients
	Name                   string         `json:"name"`
	Description            string         `json:"description,omitempty"`
	RedirectURIs           []string       `json:"redirect_uris"`
	PostLogoutRedirectURIs []string       `json:"post_logout_redirect_uris,omitempty"`
	GrantTypes             []string       `json:"grant_types"`
	Scopes                 []string       `json:"scopes"`
	IsConfidential         bool           `json:"is_confidential"`
	Metadata               map[string]any `json:"metadata,omitempty"`
	CreatedAt              time.Time      `json:"created_at"`
	UpdatedAt              time.Time      `json:"updated_at"`
	DeletedAt              *time.Time     `json:"deleted_at,omitempty"`
}

// ValidateRedirectURI validates that the redirect URI is in the registered list
func (c *OAuth2Client) ValidateRedirectURI(uri string) bool {
	for _, registered := range c.RedirectURIs {
		if subtle.ConstantTimeCompare([]byte(uri), []byte(registered)) == 1 {
			return true
		}
	}
	return false
}

// ValidatePostLogoutRedirectURI validates that the post-logout redirect URI is in the registered list
func (c *OAuth2Client) ValidatePostLogoutRedirectURI(uri string) bool {
	for _, registered := range c.PostLogoutRedirectURIs {
		if subtle.ConstantTimeCompare([]byte(uri), []byte(registered)) == 1 {
			return true
		}
	}
	return false
}

// HasGrantType checks whether the specified grant type is supported
func (c *OAuth2Client) HasGrantType(gt string) bool {
	return slices.Contains(c.GrantTypes, gt)
}

// ValidateScope validates and returns the subset of scopes supported by the client
func (c *OAuth2Client) ValidateScope(requestedScopes []string) []string {
	var valid []string
	for _, s := range requestedScopes {
		if slices.Contains(c.Scopes, s) {
			valid = append(valid, s)
		}
	}
	return valid
}

// VerifySecret verifies the client secret (via bcrypt verification)
func (c *OAuth2Client) VerifySecret(secret string, verifyFn func(hashed, plain string) bool) bool {
	if !c.IsConfidential || c.ClientSecretHash == "" {
		return false
	}
	return verifyFn(c.ClientSecretHash, secret)
}

// Grant Type constants
const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypeClientCredentials = "client_credentials"
	GrantTypeDeviceCode        = "urn:ietf:params:oauth:grant-type:device_code"
)

// Error definitions
var (
	ErrClientNotFound       = fmt.Errorf("oauth2 client not found")
	ErrInvalidRedirectURI   = fmt.Errorf("invalid redirect_uri")
	ErrUnsupportedGrantType = fmt.Errorf("unsupported grant type")
	ErrInvalidScope         = fmt.Errorf("invalid scope")
	ErrClientSecretMismatch = fmt.Errorf("client secret mismatch")
)
