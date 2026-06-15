package domain

import (
	"crypto/subtle"
	"errors"
	"net/url"
	"slices"
	"time"

	"github.com/google/uuid"
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

// ValidateRedirectURI validates that the redirect URI is in the registered list.
// Uses constant-time comparison throughout: all registered URIs are checked even
// after a match is found, to avoid leaking the matched position via timing.
func (c *OAuth2Client) ValidateRedirectURI(uri string) bool {
	if !isValidRedirectScheme(uri) {
		return false
	}
	uriBytes := []byte(uri)
	found := 0
	for _, registered := range c.RedirectURIs {
		if subtle.ConstantTimeCompare(uriBytes, []byte(registered)) == 1 {
			found = 1
		}
	}
	return found == 1
}

// ValidatePostLogoutRedirectURI validates that the post-logout redirect URI is in the registered list.
// Uses constant-time comparison throughout to avoid leaking the matched position via timing.
func (c *OAuth2Client) ValidatePostLogoutRedirectURI(uri string) bool {
	if !isValidRedirectScheme(uri) {
		return false
	}
	uriBytes := []byte(uri)
	found := 0
	for _, registered := range c.PostLogoutRedirectURIs {
		if subtle.ConstantTimeCompare(uriBytes, []byte(registered)) == 1 {
			found = 1
		}
	}
	return found == 1
}

// isValidRedirectScheme checks that the URI uses http or https scheme and has no fragment.
// RFC 6749 §3.1.2: authorization endpoint MUST NOT redirect to a URI with a fragment component.
func isValidRedirectScheme(uri string) bool {
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	if u.Fragment != "" {
		return false
	}
	return true
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

// Grant Type constants
const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypeClientCredentials = "client_credentials"
	GrantTypeDeviceCode        = "urn:ietf:params:oauth:grant-type:device_code"
)

// Error definitions
var (
	ErrClientNotFound           = errors.New("oauth2 client not found")
	ErrClientIDRequired         = errors.New("oauth2 client: client_id is required")
	ErrClientNameRequired       = errors.New("oauth2 client: name is required")
	ErrClientGrantTypesRequired = errors.New("oauth2 client: grant_types must not be empty")
	ErrAccountIDRequired        = errors.New("oauth2 client: account_id is required")
)

// NewOAuth2Client creates a new OAuth2Client with the required fields validated.
// ClientSecretHash is optional (only set for confidential clients).
// Additional fields (RedirectURIs, Scopes, etc.) should be set after construction.
func NewOAuth2Client(accountID, name, clientID string, grantTypes []string) (*OAuth2Client, error) {
	if accountID == "" {
		return nil, ErrAccountIDRequired
	}
	if clientID == "" {
		return nil, ErrClientIDRequired
	}
	if name == "" {
		return nil, ErrClientNameRequired
	}
	if len(grantTypes) == 0 {
		return nil, ErrClientGrantTypesRequired
	}
	now := time.Now()
	return &OAuth2Client{
		ID:        uuid.New().String(),
		AccountID: accountID,
		Name:      name,
		ClientID:  clientID,
		GrantTypes: grantTypes,
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}
