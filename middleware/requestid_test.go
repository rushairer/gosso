package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func setupRequestIDTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequestIDMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	return r
}

func TestRequestIDMiddleware_GeneratesUUIDWhenNoHeader(t *testing.T) {
	r := setupRequestIDTestRouter()

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	requestID := w.Header().Get(HeaderRequestID)
	assert.NotEmpty(t, requestID)
	// UUID format: 8-4-4-4-12 hex chars
	assert.Len(t, requestID, 36)
	assert.Equal(t, 4, strings.Count(requestID, "-"))
}

func TestRequestIDMiddleware_PreservesValidHeader(t *testing.T) {
	r := setupRequestIDTestRouter()

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set(HeaderRequestID, "my-custom-request-id-123")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "my-custom-request-id-123", w.Header().Get(HeaderRequestID))
}

func TestRequestIDMiddleware_ReplacesTooLongHeader(t *testing.T) {
	r := setupRequestIDTestRouter()

	longID := strings.Repeat("a", 200)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set(HeaderRequestID, longID)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	resultID := w.Header().Get(HeaderRequestID)
	assert.NotEqual(t, longID, resultID)
	assert.Len(t, resultID, 36) // Should be a new UUID
}

func TestRequestIDMiddleware_ReplacesInvalidCharacters(t *testing.T) {
	r := setupRequestIDTestRouter()

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set(HeaderRequestID, "invalid id with spaces & special!")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	resultID := w.Header().Get(HeaderRequestID)
	assert.NotEqual(t, "invalid id with spaces & special!", resultID)
	assert.Len(t, resultID, 36)
}

func TestRequestIDMiddleware_SetsContextKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequestIDMiddleware())

	var contextRequestID string
	r.GET("/test", func(c *gin.Context) {
		if rid, exists := c.Get(ContextKeyRequestID); exists {
			contextRequestID = rid.(string)
		}
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set(HeaderRequestID, "test-id-123")
	r.ServeHTTP(w, req)

	assert.Equal(t, "test-id-123", contextRequestID)
}

func TestIsValidRequestID(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"alphanumeric", "abc123", true},
		{"with hyphens", "abc-123-def", true},
		{"with underscores", "abc_123_def", true},
		{"with dots", "abc.123.def", true},
		{"mixed", "req-id_1.0", true},
		{"empty string", "", true},
		{"with spaces", "abc 123", false},
		{"with special chars", "abc@123", false},
		{"with unicode", "abcé", false},
		{"with ampersand", "a&b", false},
		{"with exclamation", "hello!", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, isValidRequestID(tt.input))
		})
	}
}
