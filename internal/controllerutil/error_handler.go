package controllerutil

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"
	"go.uber.org/zap"
)

// ErrorMapping maps a sentinel error to an HTTP status and client-facing message.
type ErrorMapping struct {
	Status  int
	Message string
}

// HandleServiceError maps a service error to an HTTP response using gouno.NewErrorResponse.
// It iterates errorMap and returns the first matching entry via errors.Is.
// If no match, it returns fallbackStatus with fallbackMsg.
// Matched errors are logged at Warn level; unmatched errors are logged at Error level.
func HandleServiceError(ctx *gin.Context, logger *zap.Logger, err error,
	errorMap map[error]ErrorMapping, fallbackStatus int, fallbackMsg string) {
	for sentinel, mapping := range errorMap {
		if errors.Is(err, sentinel) {
			logger.Warn(fallbackMsg, zap.Error(err))
			ctx.JSON(mapping.Status, gouno.NewErrorResponse(mapping.Status, mapping.Message))
			return
		}
	}
	logger.Error(fallbackMsg, zap.Error(err))
	ctx.JSON(fallbackStatus, gouno.NewErrorResponse(fallbackStatus, fallbackMsg))
}

// HandleClientAuthError handles the common OAuth2 client authentication error pattern.
// It distinguishes secretRequiredErr (e.g., ErrClientSecretRequired) from other auth errors
// and returns a 401 with "invalid_client" error code per RFC 6749.
// The caller passes the specific sentinel to check, avoiding import coupling.
func HandleClientAuthError(ctx *gin.Context, err error,
	secretRequiredErr error, secretRequiredDesc, invalidClientDesc string) {
	if errors.Is(err, secretRequiredErr) {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": secretRequiredDesc})
	} else {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": invalidClientDesc})
	}
}
