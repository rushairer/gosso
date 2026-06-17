package controllerutil

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rushairer/gouno"
)

// SetNoCacheHeaders sets HTTP headers to prevent caching of responses containing tokens.
func SetNoCacheHeaders(ctx *gin.Context) {
	ctx.Header("Cache-Control", "no-store")
	ctx.Header("Pragma", "no-cache")
}

// ValidateUUID validates and returns the UUID string, or sends a 400 error response.
func ValidateUUID(ctx *gin.Context, value, paramName string) (string, bool) {
	if _, err := uuid.Parse(value); err != nil {
		ctx.JSON(http.StatusBadRequest, gouno.NewErrorResponse(http.StatusBadRequest, "invalid "+paramName))
		return "", false
	}
	return value, true
}
