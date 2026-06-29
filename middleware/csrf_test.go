package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func setupCSRFTestRouter(secure bool, skipPaths ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(CSRFMiddleware(secure, zap.NewNop(), 0, skipPaths...))
	return r
}

func TestCSRF_GET_Skipped(t *testing.T) {
	r := setupCSRFTestRouter(false)
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	cookies := w.Header().Values("Set-Cookie")
	found := false
	for _, c := range cookies {
		if len(c) >= len(csrfCookieName) && c[:len(csrfCookieName)] == csrfCookieName {
			found = true
			break
		}
	}
	assert.True(t, found, "CSRF cookie should be set")
}

func TestCSRF_BearerAuth_Skipped(t *testing.T) {
	r := setupCSRFTestRouter(false)
	r.POST("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCSRF_SkipPath_Skipped(t *testing.T) {
	r := setupCSRFTestRouter(false, "/webhook/incoming")
	r.POST("/webhook/incoming", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/webhook/incoming", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCSRF_PasswordResetSkipPaths_Skipped(t *testing.T) {
	r := setupCSRFTestRouter(false, "/api/v1/auth/password/forgot", "/api/v1/auth/password/reset")
	r.POST("/api/v1/auth/password/forgot", func(c *gin.Context) {
		c.String(http.StatusOK, "forgot")
	})
	r.POST("/api/v1/auth/password/reset", func(c *gin.Context) {
		c.String(http.StatusOK, "reset")
	})

	for _, path := range []string{"/api/v1/auth/password/forgot", "/api/v1/auth/password/reset"} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, path, nil)
			r.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
		})
	}
}

func TestCSRF_MissingCookie_403(t *testing.T) {
	r := setupCSRFTestRouter(false)
	r.POST("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/test", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "CSRF token missing")
}

func TestCSRF_Mismatch_403(t *testing.T) {
	r := setupCSRFTestRouter(false)
	r.POST("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Cookie", csrfCookieName+"=token-from-cookie")
	req.Header.Set(csrfHeaderName, "different-token")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "CSRF token mismatch")
}

func TestCSRF_Match_200(t *testing.T) {
	r := setupCSRFTestRouter(false)
	r.POST("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	token := "valid-csrf-token-1234567890123456"
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Cookie", csrfCookieName+"="+token)
	req.Header.Set(csrfHeaderName, token)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCSRF_EmptyHeader_403(t *testing.T) {
	r := setupCSRFTestRouter(false)
	r.POST("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Cookie", csrfCookieName+"=some-token")
	// No header set
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCSRF_SecureMode_UsesHostPrefix(t *testing.T) {
	r := setupCSRFTestRouter(true)
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	cookies := w.Header().Values("Set-Cookie")
	found := false
	for _, c := range cookies {
		if len(c) >= len(csrfSecureCookieName) && c[:len(csrfSecureCookieName)] == csrfSecureCookieName {
			found = true
			break
		}
	}
	assert.True(t, found, "__Host-csrf_token cookie should be set in secure mode")
}

func TestCSRF_SecureMode_Match_200(t *testing.T) {
	r := setupCSRFTestRouter(true)
	r.POST("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	token := "valid-csrf-token-1234567890123456"
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Cookie", csrfSecureCookieName+"="+token)
	req.Header.Set(csrfHeaderName, token)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestIsPlausibleJWT_ValidJWT_WithAlg(t *testing.T) {
	// {"alg":"RS256"} base64url = eyJhbGciOiJSUzI1NiJ9
	validJWT := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
	assert.True(t, IsPlausibleJWT(validJWT))
}

func TestIsPlausibleJWT_ValidBase64_NoAlg(t *testing.T) {
	// {"typ":"JWT"} base64url = eyJ0eXAiOiJKV1QifQ — valid JSON, no "alg" field
	noAlgJWT := "eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
	assert.False(t, IsPlausibleJWT(noAlgJWT))
}

func TestIsPlausibleJWT_InvalidJSON(t *testing.T) {
	// "not-json" base64url = bm90LWpzb24 — valid base64url, not valid JSON
	badJSON := "bm90LWpzb24.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
	assert.False(t, IsPlausibleJWT(badJSON))
}

func TestIsPlausibleJWT_EmptyAlg(t *testing.T) {
	// {"alg":""} base64url = eyJhbGciOiIifQ — valid JSON, empty alg
	emptyAlgJWT := "eyJhbGciOiIifQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
	assert.False(t, IsPlausibleJWT(emptyAlgJWT))
}

func TestCSRF_BearerAuth_NoAlg_Blocked(t *testing.T) {
	r := setupCSRFTestRouter(false)
	r.POST("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	// A token with valid base64url header but no "alg" field should NOT bypass CSRF
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "Bearer eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "CSRF token missing")
}
