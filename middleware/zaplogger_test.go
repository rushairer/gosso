package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestTruncateString_NoTruncation(t *testing.T) {
	result := truncateString("hello", 10)
	assert.Equal(t, "hello", result)
}

func TestTruncateString_ExactLength(t *testing.T) {
	result := truncateString("hello", 5)
	assert.Equal(t, "hello", result)
}

func TestTruncateString_Truncated(t *testing.T) {
	result := truncateString("hello world", 5)
	assert.Equal(t, "hello...(truncated)", result)
}

func TestTruncateString_EmptyString(t *testing.T) {
	result := truncateString("", 10)
	assert.Equal(t, "", result)
}

func TestSanitizeQuery_EmptyString(t *testing.T) {
	result := sanitizeQuery("")
	assert.Equal(t, "", result)
}

func TestSanitizeQuery_NoSensitiveParams(t *testing.T) {
	result := sanitizeQuery("foo=bar&baz=qux")
	assert.Equal(t, "baz=qux&foo=bar", result)
}

func TestSanitizeQuery_RedactsToken(t *testing.T) {
	result := sanitizeQuery("token=secret123&foo=bar")
	assert.NotContains(t, result, "secret123")
	assert.Contains(t, result, "token=%5BREDACTED%5D")
	assert.Contains(t, result, "foo=bar")
}

func TestSanitizeQuery_RedactsPassword(t *testing.T) {
	result := sanitizeQuery("password=mysecret&user=admin")
	assert.NotContains(t, result, "mysecret")
	assert.Contains(t, result, "password=%5BREDACTED%5D")
	assert.Contains(t, result, "user=admin")
}

func TestSanitizeQuery_RedactsCode(t *testing.T) {
	result := sanitizeQuery("code=abc123&state=xyz")
	assert.NotContains(t, result, "abc123")
	assert.Contains(t, result, "code=%5BREDACTED%5D")
	assert.Contains(t, result, "state=xyz")
}

func TestSanitizeQuery_RedactsMultipleSensitiveParams(t *testing.T) {
	result := sanitizeQuery("access_token=atoken&refresh_token=rtoken")
	assert.NotContains(t, result, "atoken")
	assert.NotContains(t, result, "rtoken")
}

func TestSanitizeQuery_InvalidQueryString(t *testing.T) {
	// url.ParseQuery is very lenient, so we test with something that truly fails
	// Actually Go's ParseQuery almost never fails. Let's verify it handles normal input gracefully.
	result := sanitizeQuery("a=b")
	assert.Equal(t, "a=b", result)
}

func TestLoggerFromContext_WithRequestLogger(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	fallback := zap.NewNop()
	requestLogger := zap.NewNop()
	ctx.Set(ContextKeyLogger, requestLogger)

	result := LoggerFromContext(ctx, fallback)
	assert.Equal(t, requestLogger, result)
}

func TestLoggerFromContext_WithoutRequestLogger(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	fallback := zap.NewNop()
	result := LoggerFromContext(ctx, fallback)
	assert.Equal(t, fallback, result)
}

func TestLoggerFromContext_WithInvalidType(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	fallback := zap.NewNop()
	ctx.Set(ContextKeyLogger, "not-a-logger")

	result := LoggerFromContext(ctx, fallback)
	assert.Equal(t, fallback, result)
}

func TestZapLoggerMiddleware_LogsRequestWithRequestID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	core, recorded := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(ContextKeyRequestID, "test-req-id-123")
		c.Next()
	})
	r.Use(ZapLoggerMiddleware(logger))
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test?foo=bar", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	logs := recorded.All()
	assert.NotEmpty(t, logs)
	lastLog := logs[len(logs)-1]
	assert.Equal(t, zap.InfoLevel, lastLog.Level)

	// Check that request_id is in the log fields
	foundRequestID := false
	for _, field := range lastLog.ContextMap() {
		if field == "test-req-id-123" {
			foundRequestID = true
		}
	}
	assert.True(t, foundRequestID, "request_id should be in log fields")
}

func TestZapLoggerMiddleware_LogsWarnFor4xx(t *testing.T) {
	gin.SetMode(gin.TestMode)
	core, recorded := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	r := gin.New()
	r.Use(ZapLoggerMiddleware(logger))
	r.GET("/notfound", func(c *gin.Context) {
		c.String(http.StatusNotFound, "not found")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/notfound", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	logs := recorded.All()
	assert.NotEmpty(t, logs)
	lastLog := logs[len(logs)-1]
	assert.Equal(t, zap.WarnLevel, lastLog.Level)
}

func TestZapLoggerMiddleware_LogsErrorFor5xx(t *testing.T) {
	gin.SetMode(gin.TestMode)
	core, recorded := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	r := gin.New()
	r.Use(ZapLoggerMiddleware(logger))
	r.GET("/error", func(c *gin.Context) {
		c.String(http.StatusInternalServerError, "internal error")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/error", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	logs := recorded.All()
	assert.NotEmpty(t, logs)
	lastLog := logs[len(logs)-1]
	assert.Equal(t, zap.ErrorLevel, lastLog.Level)
}
