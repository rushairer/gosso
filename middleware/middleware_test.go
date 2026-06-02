package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func setupRouter(handler gin.HandlerFunc) *gin.Engine {
	r := gin.New()
	r.Use(handler)
	r.GET("/test", func(c *gin.Context) { c.String(200, "ok") })
	r.POST("/test", func(c *gin.Context) { c.String(200, "ok") })
	return r
}

// ──────────────────────────────────────────────
// RequestIDMiddleware
// ──────────────────────────────────────────────

func TestRequestID_GeneratesNew(t *testing.T) {
	r := setupRouter(RequestIDMiddleware())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	rid := w.Header().Get(HeaderRequestID)
	assert.NotEmpty(t, rid)
	assert.Len(t, rid, 36) // UUID format
}

func TestRequestID_PreservesExisting(t *testing.T) {
	r := setupRouter(RequestIDMiddleware())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set(HeaderRequestID, "my-custom-id")
	r.ServeHTTP(w, req)

	assert.Equal(t, "my-custom-id", w.Header().Get(HeaderRequestID))
}

func TestRequestID_SetsContext(t *testing.T) {
	var captured string
	r := gin.New()
	r.Use(RequestIDMiddleware())
	r.GET("/test", func(c *gin.Context) {
		rid, exists := c.Get(ContextKeyRequestID)
		if exists {
			captured = rid.(string)
		}
		c.String(200, "ok")
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	assert.NotEmpty(t, captured)
	assert.Equal(t, w.Header().Get(HeaderRequestID), captured)
}

// ──────────────────────────────────────────────
// ZapLoggerMiddleware
// ──────────────────────────────────────────────

func TestZapLogger_SuccessRequest(t *testing.T) {
	logger := zap.NewNop()
	r := gin.New()
	r.Use(RequestIDMiddleware())
	r.Use(ZapLoggerMiddleware(logger))
	r.GET("/test", func(c *gin.Context) { c.String(200, "ok") })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test?foo=bar", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}

func TestZapLogger_WithAccountID(t *testing.T) {
	logger := zap.NewNop()
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("account_id", "account-001")
		c.Next()
	})
	r.Use(ZapLoggerMiddleware(logger))
	r.GET("/test", func(c *gin.Context) { c.String(200, "ok") })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}

func TestZapLogger_ErrorStatus(t *testing.T) {
	logger := zap.NewNop()
	r := gin.New()
	r.Use(ZapLoggerMiddleware(logger))
	r.GET("/test", func(c *gin.Context) { c.String(500, "error") })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, 500, w.Code)
}

func TestZapLogger_WarnStatus(t *testing.T) {
	logger := zap.NewNop()
	r := gin.New()
	r.Use(ZapLoggerMiddleware(logger))
	r.GET("/test", func(c *gin.Context) { c.String(404, "not found") })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, 404, w.Code)
}

// ──────────────────────────────────────────────
// generateCSRFToken
// ──────────────────────────────────────────────

func TestGenerateCSRFToken_Length(t *testing.T) {
	token := generateCSRFToken()
	require.Len(t, token, 64) // 32 bytes = 64 hex chars
}

func TestGenerateCSRFToken_Unique(t *testing.T) {
	t1 := generateCSRFToken()
	t2 := generateCSRFToken()
	assert.NotEqual(t, t1, t2)
}
