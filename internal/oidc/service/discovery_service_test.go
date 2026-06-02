package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDiscoveryService(t *testing.T) {
	svc := NewDiscoveryService("https://sso.example.com")
	require.NotNil(t, svc)
}

func TestGetDiscoveryDocument_ContainsIssuer(t *testing.T) {
	svc := NewDiscoveryService("https://sso.example.com")
	doc := svc.GetDiscoveryDocument()

	assert.Equal(t, "https://sso.example.com", doc["issuer"])
}

func TestGetDiscoveryDocument_Endpoints(t *testing.T) {
	svc := NewDiscoveryService("https://sso.example.com")
	doc := svc.GetDiscoveryDocument()

	assert.Equal(t, "https://sso.example.com/oauth2/authorize", doc["authorization_endpoint"])
	assert.Equal(t, "https://sso.example.com/oauth2/token", doc["token_endpoint"])
	assert.Equal(t, "https://sso.example.com/.well-known/jwks.json", doc["jwks_uri"])
	assert.Equal(t, "https://sso.example.com/oidc/userinfo", doc["userinfo_endpoint"])
}

func TestGetDiscoveryDocument_SupportedValues(t *testing.T) {
	svc := NewDiscoveryService("https://sso.example.com")
	doc := svc.GetDiscoveryDocument()

	assert.Contains(t, doc["scopes_supported"], "openid")
	assert.Contains(t, doc["scopes_supported"], "profile")
	assert.Contains(t, doc["scopes_supported"], "email")
	assert.Contains(t, doc["scopes_supported"], "phone")

	assert.Contains(t, doc["response_types_supported"], "code")

	assert.Contains(t, doc["grant_types_supported"], "authorization_code")
	assert.Contains(t, doc["grant_types_supported"], "refresh_token")
	assert.Contains(t, doc["grant_types_supported"], "client_credentials")

	assert.Contains(t, doc["subject_types_supported"], "public")
	assert.Contains(t, doc["id_token_signing_alg_values_supported"], "RS256")
	assert.Contains(t, doc["code_challenge_methods_supported"], "S256")
}

func TestGetDiscoveryDocument_TokenEndpointAuthMethods(t *testing.T) {
	svc := NewDiscoveryService("https://sso.example.com")
	doc := svc.GetDiscoveryDocument()

	methods, ok := doc["token_endpoint_auth_methods_supported"].([]string)
	require.True(t, ok)
	assert.Contains(t, methods, "client_secret_post")
	assert.Contains(t, methods, "client_secret_basic")
}

func TestGetDiscoveryDocument_ClaimsSupported(t *testing.T) {
	svc := NewDiscoveryService("https://sso.example.com")
	doc := svc.GetDiscoveryDocument()

	claims, ok := doc["claims_supported"].([]string)
	require.True(t, ok)
	for _, c := range []string{"sub", "iss", "aud", "exp", "iat", "name", "email", "email_verified", "phone_number", "locale"} {
		assert.Contains(t, claims, c)
	}
}

func TestGetDiscoveryDocument_DifferentIssuer(t *testing.T) {
	svc := NewDiscoveryService("http://localhost:8080")
	doc := svc.GetDiscoveryDocument()

	assert.Equal(t, "http://localhost:8080", doc["issuer"])
	assert.Equal(t, "http://localhost:8080/oauth2/authorize", doc["authorization_endpoint"])
}

func TestGetDiscoveryDocument_EndSessionEndpoint(t *testing.T) {
	svc := NewDiscoveryService("https://sso.example.com")
	doc := svc.GetDiscoveryDocument()

	assert.Equal(t, "https://sso.example.com/oidc/logout", doc["end_session_endpoint"])
}

func TestGetDiscoveryDocument_EndSessionEndpoint_Localhost(t *testing.T) {
	svc := NewDiscoveryService("http://localhost:8080")
	doc := svc.GetDiscoveryDocument()

	assert.Equal(t, "http://localhost:8080/oidc/logout", doc["end_session_endpoint"])
}
