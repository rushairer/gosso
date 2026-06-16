package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/rushairer/gouno"
)

// RequireAccountID extracts the authenticated account ID from the gin context.
// Returns the account ID and true on success, or responds with 401 and aborts the request.
func RequireAccountID(ctx *gin.Context) (string, bool) {
	raw, exists := ctx.Get(ContextKeyAccountID)
	if !exists {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "unauthorized"))
		return "", false
	}
	accountID, ok := raw.(string)
	if !ok || accountID == "" {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "unauthorized"))
		return "", false
	}
	return accountID, true
}

// GetAccountID is an alias for RequireAccountID.
// Deprecated: Use RequireAccountID instead.
func GetAccountID(ctx *gin.Context) (string, bool) {
	return RequireAccountID(ctx)
}
