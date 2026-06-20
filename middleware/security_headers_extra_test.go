package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestSecurityHeadersMiddleware_CSPUpgradeInsecureRequestsOnlyInProduction(t *testing.T) {
	t.Run("development", func(t *testing.T) {
		r := gin.New()
		r.Use(SecurityHeadersMiddleware(false))
		r.GET("/test", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.NotContains(t, w.Header().Get("Content-Security-Policy"), "upgrade-insecure-requests")
	})

	t.Run("production", func(t *testing.T) {
		r := gin.New()
		r.Use(SecurityHeadersMiddleware(true))
		r.GET("/test", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Header().Get("Content-Security-Policy"), "upgrade-insecure-requests")
	})
}
