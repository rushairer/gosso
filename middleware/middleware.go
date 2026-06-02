package middleware

import (
	"net/http"
	"runtime/debug"
	"time"

	"github.com/gin-contrib/timeout"
	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"
	"go.uber.org/zap"
)

func TimeoutMiddleware(requestTimeout time.Duration) gin.HandlerFunc {
	return timeout.New(
		timeout.WithTimeout(requestTimeout),
		timeout.WithResponse(
			func(ctx *gin.Context) {
				ctx.JSON(http.StatusRequestTimeout, gouno.RequestTimeoutResponse)
			},
		),
	)
}

func RecoveryMiddleware(logger *zap.Logger) gin.HandlerFunc {
	if logger == nil {
		logger = zap.NewNop()
	}
	return gin.CustomRecovery(
		func(ctx *gin.Context, err any) {
			logger.Error("panic recovered",
				zap.Any("error", err),
				zap.String("stack", string(debug.Stack())),
				zap.String("path", ctx.Request.URL.Path),
				zap.String("method", ctx.Request.Method),
			)
			ctx.JSON(http.StatusInternalServerError, gouno.InternalServerErrorResponse)
		},
	)
}
