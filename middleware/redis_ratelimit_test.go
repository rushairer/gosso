package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestIPKeyFunc(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request, _ = http.NewRequest("GET", "/", nil)
	ctx.Request.RemoteAddr = "192.168.1.1:12345"

	key := IPKeyFunc(ctx)
	assert.NotEmpty(t, key)
}

func TestIPKeyFunc_Localhost(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request, _ = http.NewRequest("GET", "/", nil)
	ctx.Request.RemoteAddr = "127.0.0.1:8080"

	key := IPKeyFunc(ctx)
	assert.Equal(t, "127.0.0.1", key)
}

func TestIPKeyFunc_XForwardedFor(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request, _ = http.NewRequest("GET", "/", nil)
	ctx.Request.RemoteAddr = "10.0.0.1:12345"
	ctx.Request.Header.Set("X-Forwarded-For", "203.0.113.50")

	key := IPKeyFunc(ctx)
	assert.Equal(t, "203.0.113.50", key)
}
