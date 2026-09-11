package gosso

import "testing"

func TestDefaultCSRFSkipPathsKeepOAuthClientEndpointsOutsideBrowserCSRF(t *testing.T) {
	paths := make(map[string]struct{})
	for _, path := range defaultCSRFSkipPaths() {
		paths[path] = struct{}{}
	}

	for _, path := range []string{
		"/oauth2/token",
		"/oauth2/revoke",
		"/oauth2/introspect",
		"/oauth2/device/code",
	} {
		if _, ok := paths[path]; !ok {
			t.Fatalf("OAuth client protocol endpoint %q must bypass browser CSRF middleware", path)
		}
	}

	for _, path := range []string{
		"/oidc/logout",
		"/api/v1/auth/logout",
	} {
		if _, ok := paths[path]; ok {
			t.Fatalf("browser/session endpoint %q must remain subject to CSRF unless authenticated by an exempt source", path)
		}
	}
}
