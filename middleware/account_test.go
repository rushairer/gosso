package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func setupAccountTestContext() (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	return ctx, w
}

func TestRequireAccountID_WithValidAccountID(t *testing.T) {
	ctx, _ := setupAccountTestContext()
	ctx.Set(ContextKeyAccountID, "account-123")

	accountID, ok := RequireAccountID(ctx)

	assert.True(t, ok)
	assert.Equal(t, "account-123", accountID)
	assert.Equal(t, http.StatusOK, ctx.Writer.Status())
}

func TestRequireAccountID_WithNoAccountID(t *testing.T) {
	ctx, w := setupAccountTestContext()

	accountID, ok := RequireAccountID(ctx)

	assert.False(t, ok)
	assert.Empty(t, accountID)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireAccountID_WithEmptyString(t *testing.T) {
	ctx, w := setupAccountTestContext()
	ctx.Set(ContextKeyAccountID, "")

	accountID, ok := RequireAccountID(ctx)

	assert.False(t, ok)
	assert.Empty(t, accountID)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireAccountID_WithNonStringType(t *testing.T) {
	ctx, w := setupAccountTestContext()
	ctx.Set(ContextKeyAccountID, 12345)

	accountID, ok := RequireAccountID(ctx)

	assert.False(t, ok)
	assert.Empty(t, accountID)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
