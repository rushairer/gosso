package service

// DiscoveryService OIDC Discovery service
type DiscoveryService struct {
	issuer           string
	authEndpoint     string
	tokenEndpoint    string
	jwksURI          string
	userInfoEndpoint string
}

// NewDiscoveryService creates a new instance of DiscoveryService
func NewDiscoveryService(issuer string) *DiscoveryService {
	return &DiscoveryService{
		issuer:           issuer,
		authEndpoint:     issuer + "/oauth2/authorize",
		tokenEndpoint:    issuer + "/oauth2/token",
		jwksURI:          issuer + "/.well-known/jwks.json",
		userInfoEndpoint: issuer + "/oidc/userinfo",
	}
}

// GetDiscoveryDocument returns the OIDC Discovery document
func (s *DiscoveryService) GetDiscoveryDocument() map[string]any {
	return map[string]any{
		"issuer":                 s.issuer,
		"authorization_endpoint": s.authEndpoint,
		"token_endpoint":         s.tokenEndpoint,
		"jwks_uri":               s.jwksURI,
		"userinfo_endpoint":      s.userInfoEndpoint,
		"scopes_supported": []string{
			"openid", "profile", "email", "phone",
		},
		"response_types_supported": []string{
			"code",
		},
		"grant_types_supported": []string{
			"authorization_code", "refresh_token", "client_credentials",
		},
		"subject_types_supported": []string{
			"public",
		},
		"id_token_signing_alg_values_supported": []string{
			"RS256",
		},
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_post", "client_secret_basic",
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
	}
}
