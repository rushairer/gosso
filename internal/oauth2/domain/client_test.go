package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func newTestClient() *OAuth2Client {
	return &OAuth2Client{
		ClientID:         "test-client",
		RedirectURIs:     []string{"https://app.example.com/callback", "https://app.example.com/oauth2/callback"},
		GrantTypes:       []string{"authorization_code", "refresh_token"},
		Scopes:           []string{"openid", "profile", "email"},
		IsConfidential:   true,
		ClientSecretHash: "$2a$10$fakehash",
	}
}

// ──────────────────────────────────────────────
// ValidateRedirectURI
// ──────────────────────────────────────────────

func TestValidateRedirectURI_Valid(t *testing.T) {
	c := newTestClient()
	assert.True(t, c.ValidateRedirectURI("https://app.example.com/callback"))
	assert.True(t, c.ValidateRedirectURI("https://app.example.com/oauth2/callback"))
}

func TestValidateRedirectURI_Invalid(t *testing.T) {
	c := newTestClient()
	assert.False(t, c.ValidateRedirectURI("https://evil.com/callback"))
	assert.False(t, c.ValidateRedirectURI(""))
	assert.False(t, c.ValidateRedirectURI("https://app.example.com/other"))
}

func TestValidateRedirectURI_EmptyList(t *testing.T) {
	c := &OAuth2Client{RedirectURIs: []string{}}
	assert.False(t, c.ValidateRedirectURI("https://app.example.com/callback"))
}

// ──────────────────────────────────────────────
// HasGrantType
// ──────────────────────────────────────────────

func TestHasGrantType_Supported(t *testing.T) {
	c := newTestClient()
	assert.True(t, c.HasGrantType("authorization_code"))
	assert.True(t, c.HasGrantType("refresh_token"))
}

func TestHasGrantType_Unsupported(t *testing.T) {
	c := newTestClient()
	assert.False(t, c.HasGrantType("client_credentials"))
	assert.False(t, c.HasGrantType(""))
}

// ──────────────────────────────────────────────
// ValidateScope
// ──────────────────────────────────────────────

func TestValidateScope_AllValid(t *testing.T) {
	c := newTestClient()
	result := c.ValidateScope([]string{"openid", "profile"})
	assert.Equal(t, []string{"openid", "profile"}, result)
}

func TestValidateScope_PartialValid(t *testing.T) {
	c := newTestClient()
	result := c.ValidateScope([]string{"openid", "admin"})
	assert.Equal(t, []string{"openid"}, result)
}

func TestValidateScope_NoneValid(t *testing.T) {
	c := newTestClient()
	result := c.ValidateScope([]string{"admin", "superuser"})
	assert.Nil(t, result)
}

func TestValidateScope_Empty(t *testing.T) {
	c := newTestClient()
	result := c.ValidateScope([]string{})
	assert.Nil(t, result)
}

// ──────────────────────────────────────────────
// ValidatePostLogoutRedirectURI
// ──────────────────────────────────────────────

func TestValidatePostLogoutRedirectURI_Valid(t *testing.T) {
	c := &OAuth2Client{
		PostLogoutRedirectURIs: []string{"https://app.example.com/logout", "https://app.example.com/bye"},
	}
	assert.True(t, c.ValidatePostLogoutRedirectURI("https://app.example.com/logout"))
	assert.True(t, c.ValidatePostLogoutRedirectURI("https://app.example.com/bye"))
}

func TestValidatePostLogoutRedirectURI_NoMatch(t *testing.T) {
	c := &OAuth2Client{
		PostLogoutRedirectURIs: []string{"https://app.example.com/logout"},
	}
	assert.False(t, c.ValidatePostLogoutRedirectURI("https://evil.com/logout"))
}

func TestValidatePostLogoutRedirectURI_EmptyList(t *testing.T) {
	c := &OAuth2Client{PostLogoutRedirectURIs: []string{}}
	assert.False(t, c.ValidatePostLogoutRedirectURI("https://app.example.com/logout"))
}

// ──────────────────────────────────────────────
// isValidRedirectScheme edge cases
// ──────────────────────────────────────────────

func TestValidateRedirectURI_WithFragment(t *testing.T) {
	c := newTestClient()
	assert.False(t, c.ValidateRedirectURI("https://app.example.com/callback#fragment"))
}
