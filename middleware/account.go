package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/rushairer/gouno"
)

// GetAccountID extracts the authenticated account ID from the gin context.
// Returns the account ID and true on success, or responds with 401 and returns ("", false) on failure.
func GetAccountID(ctx *gin.Context) (string, bool) {
	raw, exists := ctx.Get(ContextKeyAccountID)
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "unauthorized"))
		return "", false
	}
	accountID, ok := raw.(string)
	if !ok || accountID == "" {
		ctx.JSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "unauthorized"))
		return "", false
	}
	return accountID, true
}
