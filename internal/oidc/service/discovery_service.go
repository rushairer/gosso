package service

import "encoding/json"

// DiscoveryService OIDC Discovery service
type DiscoveryService struct {
	jsonBytes []byte
}

// NewDiscoveryService creates a new instance of DiscoveryService.
// The discovery document is pre-marshaled to JSON once since it is static
// for the lifetime of the service. This avoids per-request map copying and
// JSON marshaling.
func NewDiscoveryService(issuer string) *DiscoveryService {
	doc := map[string]any{
		"issuer":                        issuer,
		"authorization_endpoint":        issuer + "/oauth2/authorize",
		"token_endpoint":                issuer + "/oauth2/token",
		"jwks_uri":                      issuer + "/.well-known/jwks.json",
		"userinfo_endpoint":             issuer + "/oidc/userinfo",
		"end_session_endpoint":          issuer + "/oidc/logout",
		"device_authorization_endpoint": issuer + "/oauth2/device/code",
		"scopes_supported": []string{
			"openid", "profile", "email", "phone",
		},
		"response_modes_supported": []string{
			"query",
		},
		"response_types_supported": []string{
			"code",
		},
		"grant_types_supported": []string{
			"authorization_code", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:device_code",
		},
		"subject_types_supported": []string{
			"public",
		},
		"id_token_signing_alg_values_supported": []string{
			"RS256",
		},
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_post", "client_secret_basic", "none",
		},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
			"name", "preferred_username", "picture",
			"email", "email_verified",
			"phone_number", "phone_number_verified",
			"locale",
		},
		"code_challenge_methods_supported": []string{
			"S256",
		},
		"revocation_endpoint": issuer + "/oauth2/revoke",
		"revocation_endpoint_auth_methods_supported": []string{
			"client_secret_post", "client_secret_basic",
		},
		"introspection_endpoint": issuer + "/oauth2/introspect",
		"introspection_endpoint_auth_methods_supported": []string{
			"client_secret_post", "client_secret_basic",
		},
		"authorization_response_iss_parameter_supported": true,
		"frontchannel_logout_supported":                true,
		"frontchannel_logout_session_supported":        true,
		"backchannel_logout_supported":                 true,
	}

	jsonBytes, err := json.Marshal(doc)
	if err != nil {
		panic("discovery service: failed to marshal discovery document: " + err.Error())
	}

	return &DiscoveryService{jsonBytes: jsonBytes}
}

// GetDiscoveryDocument returns the pre-computed JSON bytes of the OIDC Discovery document.
// Safe for concurrent use — the returned slice must not be modified by callers.
func (s *DiscoveryService) GetDiscoveryDocument() []byte {
	return s.jsonBytes
}
