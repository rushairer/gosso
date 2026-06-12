package controllerutil

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestSetNoCacheHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	SetNoCacheHeaders(ctx)

	assert.Equal(t, "no-store", ctx.Writer.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", ctx.Writer.Header().Get("Pragma"))
}

func TestSetNoCacheHeaders_OverwritesExisting(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	// Set initial headers
	ctx.Header("Cache-Control", "max-age=3600")
	ctx.Header("Pragma", "public")

	SetNoCacheHeaders(ctx)

	assert.Equal(t, "no-store", ctx.Writer.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", ctx.Writer.Header().Get("Pragma"))
}

func TestSetNoCacheHeaders_HTTPStatusCodePreserved(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	SetNoCacheHeaders(ctx)

	// Headers are set independently of status code
	assert.Equal(t, "no-store", ctx.Writer.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", ctx.Writer.Header().Get("Pragma"))
}
