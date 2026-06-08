package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
	token, err := generateCSRFToken()
	require.NoError(t, err)
	require.Len(t, token, 64) // 32 bytes = 64 hex chars
}

func TestGenerateCSRFToken_Unique(t *testing.T) {
	t1, err := generateCSRFToken()
	require.NoError(t, err)
	t2, err := generateCSRFToken()
	require.NoError(t, err)
	assert.NotEqual(t, t1, t2)
}
func TestRecoveryMiddleware_Panic(t *testing.T) {
	logger := zap.NewNop()
	r := gin.New()
	r.Use(RecoveryMiddleware(logger))
	r.GET("/panic", func(_ *gin.Context) { panic("test panic") })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/panic", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRecoveryMiddleware_NoPanic(t *testing.T) {
	logger := zap.NewNop()
	r := gin.New()
	r.Use(RecoveryMiddleware(logger))
	r.GET("/ok", func(c *gin.Context) { c.String(200, "ok") })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/ok", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}

// ──────────────────────────────────────────────
// SecurityHeadersMiddleware
// ──────────────────────────────────────────────

func TestSecurityHeadersMiddleware_Dev(t *testing.T) {
	r := gin.New()
	r.Use(SecurityHeadersMiddleware(false))
	r.GET("/test", func(c *gin.Context) { c.String(200, "ok") })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "strict-origin-when-cross-origin", w.Header().Get("Referrer-Policy"))
	assert.Equal(t, "same-origin", w.Header().Get("Cross-Origin-Opener-Policy"))
	assert.Empty(t, w.Header().Get("Strict-Transport-Security"))
}

func TestSecurityHeadersMiddleware_Prod(t *testing.T) {
	r := gin.New()
	r.Use(SecurityHeadersMiddleware(true))
	r.GET("/test", func(c *gin.Context) { c.String(200, "ok") })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.NotEmpty(t, w.Header().Get("Strict-Transport-Security"))
	assert.Contains(t, w.Header().Get("Strict-Transport-Security"), "max-age=31536000")
}

func TestSecurityHeadersMiddleware_CSPNonce(t *testing.T) {
	r := gin.New()
	r.Use(SecurityHeadersMiddleware(false))
	r.GET("/test", func(c *gin.Context) {
		nonce := GetCSPNonce(c)
		c.String(200, nonce)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	body := w.Body.String()
	assert.NotEmpty(t, body)
	cspHeader := w.Header().Get("Content-Security-Policy")
	assert.Contains(t, cspHeader, "'nonce-"+body+"'")
}

// ──────────────────────────────────────────────
// MaxBodySizeMiddleware
// ──────────────────────────────────────────────

func TestMaxBodySizeMiddleware_UnderLimit(t *testing.T) {
	r := gin.New()
	r.Use(MaxBodySizeMiddleware(1024))
	r.POST("/test", func(c *gin.Context) { c.String(200, "ok") })

	w := httptest.NewRecorder()
	body := strings.NewReader("small body")
	req, _ := http.NewRequest("POST", "/test", body)
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}

func TestMaxBodySizeMiddleware_OverLimit(t *testing.T) {
	var readErr error
	r := gin.New()
	r.Use(MaxBodySizeMiddleware(5))
	r.POST("/test", func(c *gin.Context) {
		_, readErr = io.ReadAll(c.Request.Body)
		c.String(200, "ok")
	})

	w := httptest.NewRecorder()
	body := strings.NewReader("this body is longer than five bytes")
	req, _ := http.NewRequest("POST", "/test", body)
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	require.Error(t, readErr)
	assert.Contains(t, readErr.Error(), "request body too large")
}

// ──────────────────────────────────────────────
// GetAccountID
// ──────────────────────────────────────────────

func TestGetAccountID_Success(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Set(ContextKeyAccountID, "account-123")

	id, ok := GetAccountID(ctx)
	assert.True(t, ok)
	assert.Equal(t, "account-123", id)
}

func TestGetAccountID_Missing(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	id, ok := GetAccountID(ctx)
	assert.False(t, ok)
	assert.Empty(t, id)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetAccountID_Empty(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Set(ContextKeyAccountID, "")

	id, ok := GetAccountID(ctx)
	assert.False(t, ok)
	assert.Empty(t, id)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetAccountID_WrongType(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Set(ContextKeyAccountID, 12345)

	id, ok := GetAccountID(ctx)
	assert.False(t, ok)
	assert.Empty(t, id)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ──────────────────────────────────────────────
// CSP nonce helpers
// ──────────────────────────────────────────────

func TestGetCSPNonce_NotSet(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	nonce := GetCSPNonce(ctx)
	assert.Empty(t, nonce)
}

func TestGenerateCSPNonce_Unique(t *testing.T) {
	n1 := generateCSPNonce()
	n2 := generateCSPNonce()
	assert.NotEqual(t, n1, n2)
	assert.NotEmpty(t, n1)
	assert.NotEmpty(t, n2)
}
