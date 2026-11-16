package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestLegacyAPIRedirectMiddleware_RoutingAndCSRFOrder(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name, method, path, location string
		status                       int
	}{
		{"login POST", http.MethodPost, "/api/auth/login", "/api/v1/auth/login", http.StatusPermanentRedirect},
		{"query preserved", http.MethodPost, "/api/auth/login?next=%2Fhome&x=1", "/api/v1/auth/login?next=%2Fhome&x=1", http.StatusPermanentRedirect},
		{"admin mutation", http.MethodDelete, "/api/admin/accounts/123", "/api/v1/admin/accounts/123", http.StatusPermanentRedirect},
		{"passkey singular", http.MethodPost, "/api/passkey/login/begin", "/api/v1/passkey/login/begin", http.StatusPermanentRedirect},
		{"passkeys collection", http.MethodGet, "/api/passkeys", "/api/v1/passkeys", http.StatusPermanentRedirect},
		{"passkeys member", http.MethodDelete, "/api/passkeys/123", "/api/v1/passkeys/123", http.StatusPermanentRedirect},
		{"client collection", http.MethodGet, "/api/oauth2/clients", "/api/v1/oauth2/clients", http.StatusPermanentRedirect},
		{"client member", http.MethodPut, "/api/oauth2/clients/123", "/api/v1/oauth2/clients/123", http.StatusPermanentRedirect},
		{"encoded query and path", http.MethodGet, "/api/admin/accounts/a%2Fb?value=%2B", "/api/v1/admin/accounts/a%2Fb?value=%2B", http.StatusPermanentRedirect},
		{"canonical route unaffected", http.MethodPost, "/api/v1/auth/login", "", http.StatusNoContent},
		{"future version not downgraded", http.MethodPost, "/api/v2/auth/login", "", http.StatusNotFound},
		{"unknown API path", http.MethodGet, "/api/other/path", "", http.StatusNotFound},
		{"prefix collision", http.MethodGet, "/api/authentication/login", "", http.StatusNotFound},
		{"standard protocol route", http.MethodGet, "/oauth2/authorize", "", http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := gin.New()
			r.Use(LegacyAPIRedirectMiddleware())
			// Simulate a subsequent CSRF gate. A legacy unsafe request must
			// redirect before this gate runs, without reaching the handler.
			r.Use(func(c *gin.Context) {
				if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
					c.AbortWithStatus(http.StatusForbidden)
					return
				}
				c.Next()
			})
			r.POST("/api/v1/auth/login", func(c *gin.Context) {
				c.Status(http.StatusNoContent)
			})
			w := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, tt.path, nil)
			r.ServeHTTP(w, req)
			if tt.name == "canonical route unaffected" {
				// The simulated CSRF gate intentionally protects this path.
				if w.Code != http.StatusForbidden {
					t.Fatalf("canonical request must be protected by CSRF: got %d", w.Code)
				}
				return
			}
			if w.Code != tt.status {
				t.Fatalf("status: got %d, want %d", w.Code, tt.status)
			}
			if w.Code == http.StatusPermanentRedirect && w.Header().Get("Location") != tt.location {
				t.Fatalf("location: got %q, want %q", w.Header().Get("Location"), tt.location)
			}
		})
	}
}

func TestIsLegacyAPIPathBoundaries(t *testing.T) {
	for _, path := range []string{"/api", "/api/", "/api/v1", "/api/v1/auth/login", "/api/v2/auth/login", "/api/auth", "/api/admin", "/api/passkey", "/api/passkeys-extra", "/api/oauth2/clients-extra"} {
		if isLegacyAPIPath(path) {
			t.Errorf("%q must not redirect", path)
		}
	}
}
