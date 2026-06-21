package service

// DiscoveryService OIDC Discovery service
type DiscoveryService struct {
	doc map[string]any
}

// NewDiscoveryService creates a new instance of DiscoveryService.
// The discovery document is pre-computed once since it is static for the lifetime of the service.
func NewDiscoveryService(issuer string) *DiscoveryService {
	s := &DiscoveryService{}
	s.doc = map[string]any{
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
	}
	return s
}

// GetDiscoveryDocument returns a copy of the OIDC Discovery document.
// Returns a copy to prevent callers from mutating the shared state.
func (s *DiscoveryService) GetDiscoveryDocument() map[string]any {
	return copyMap(s.doc)
}

// copyMap performs a deep copy of a map[string]any, cloning slice values
// to prevent concurrent handlers from mutating the shared state.
func copyMap(m map[string]any) map[string]any {
	cp := make(map[string]any, len(m))
	for k, v := range m {
		switch val := v.(type) {
		case []string:
			clone := make([]string, len(val))
			copy(clone, val)
			cp[k] = clone
		default:
			cp[k] = v
		}
	}
	return cp
}
