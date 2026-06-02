package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func setupCSRFTestRouter(secure bool, skipPaths ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(CSRFMiddleware(secure, skipPaths...))
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
	req.Header.Set("Authorization", "Bearer some-jwt-token")
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
