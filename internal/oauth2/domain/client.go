package domain

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// OAuth2Client OAuth2 client entity
type OAuth2Client struct {
	ID                                string         `json:"id"`
	AccountID                         string         `json:"account_id"`
	ClientID                          string         `json:"client_id"`
	ClientSecretHash                  string         `json:"-"` // Only has value for confidential clients
	Name                              string         `json:"name"`
	Description                       string         `json:"description,omitempty"`
	RedirectURIs                      []string       `json:"redirect_uris"`
	PostLogoutRedirectURIs            []string       `json:"post_logout_redirect_uris,omitempty"`
	GrantTypes                        []string       `json:"grant_types"`
	Scopes                            []string       `json:"scopes"`
	IsConfidential                    bool           `json:"is_confidential"`
	Metadata                          map[string]any `json:"metadata"`
	FrontchannelLogoutURI             string         `json:"frontchannel_logout_uri,omitempty"`
	FrontchannelLogoutSessionRequired bool           `json:"frontchannel_logout_session_required,omitempty"`
	BackchannelLogoutURI              string         `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired  bool           `json:"backchannel_logout_session_required,omitempty"`
	CreatedAt                         time.Time      `json:"created_at"`
	UpdatedAt                         time.Time      `json:"updated_at"`
	DeletedAt                         *time.Time     `json:"deleted_at,omitempty"`
}

const (
	ClientCapabilityMetadataKey = "capability"
	ClientCapabilityAdmin       = "admin"
	ScopeAdmin                  = "admin"
	adminScopePrefix            = "admin:"
)

// ValidateRedirectURI validates that the redirect URI is in the registered list.
// Uses constant-time comparison throughout: all registered URIs are checked even
// after a match is found, to avoid leaking the matched position via timing.
func (c *OAuth2Client) ValidateRedirectURI(uri string) bool {
	if c == nil || !isValidRedirectScheme(uri) {
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
	if c == nil || !isValidRedirectScheme(uri) {
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

// isValidRedirectScheme checks that the URI uses http or https scheme, has no fragment,
// and restricts http:// to loopback addresses only (RFC 9700 §2.1).
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
	// RFC 9700 §2.1: HTTP is only allowed for loopback addresses (native app development).
	if u.Scheme == "http" && !IsLoopback(u.Hostname()) {
		return false
	}
	return true
}

// IsLoopback checks if a hostname is a loopback address.
func IsLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// HasGrantType checks whether the specified grant type is supported
func (c *OAuth2Client) HasGrantType(gt string) bool {
	if c == nil {
		return false
	}
	return slices.Contains(c.GrantTypes, gt)
}

// ValidateScope validates and returns the subset of scopes supported by the client
func (c *OAuth2Client) ValidateScope(requestedScopes []string) []string {
	if c == nil {
		return nil
	}
	var valid []string
	for _, s := range requestedScopes {
		if IsAdminScope(s) && !c.HasAdminCapability() {
			continue
		}
		if slices.Contains(c.Scopes, s) {
			valid = append(valid, s)
		}
	}
	return valid
}

func (c *OAuth2Client) HasAdminCapability() bool {
	if c == nil || c.Metadata == nil {
		return false
	}
	capability, ok := c.Metadata[ClientCapabilityMetadataKey].(string)
	return ok && capability == ClientCapabilityAdmin
}

func IsAdminScope(scope string) bool {
	return scope == ScopeAdmin || strings.HasPrefix(scope, adminScopePrefix)
}

// Grant Type constants
const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypeClientCredentials = "client_credentials"
	GrantTypeDeviceCode        = "urn:ietf:params:oauth:grant-type:device_code"
)

// IsValidGrantType reports whether gt is a known OAuth2 grant type.
func IsValidGrantType(gt string) bool {
	switch gt {
	case GrantTypeAuthorizationCode, GrantTypeRefreshToken,
		GrantTypeClientCredentials, GrantTypeDeviceCode:
		return true
	}
	return false
}

// Error definitions
var (
	ErrClientNotFound               = errors.New("oauth2 client not found")
	ErrClientIDRequired             = errors.New("oauth2 client: client_id is required")
	ErrClientNameRequired           = errors.New("oauth2 client: name is required")
	ErrClientGrantTypesRequired     = errors.New("oauth2 client: grant_types must not be empty")
	ErrClientAccountIDRequired      = errors.New("oauth2 client: account_id is required")
	ErrClientConcurrentModification = errors.New("oauth2 client was modified concurrently")
	ErrClientInvalidGrantType       = errors.New("oauth2 client: invalid grant type")
)

// NewOAuth2Client creates a new OAuth2Client with the required fields validated.
// ClientSecretHash is optional (only set for confidential clients).
// Additional fields (RedirectURIs, Scopes, etc.) should be set after construction.
func NewOAuth2Client(accountID, name, clientID string, grantTypes []string) (*OAuth2Client, error) {
	if accountID == "" {
		return nil, ErrClientAccountIDRequired
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
	for _, gt := range grantTypes {
		if !IsValidGrantType(gt) {
			return nil, fmt.Errorf("%w: %s", ErrClientInvalidGrantType, gt)
		}
	}
	now := time.Now()
	return &OAuth2Client{
		ID:         uuid.New().String(),
		AccountID:  accountID,
		Name:       name,
		ClientID:   clientID,
		GrantTypes: grantTypes,
		Metadata:   make(map[string]any),
		Scopes:     []string{},
		CreatedAt:  now,
		UpdatedAt:  now,
	}, nil
}
