package middleware

import (
	"net/http"
	"time"

	"github.com/gin-contrib/timeout"
	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"
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

func RecoveryMiddleware() gin.HandlerFunc {
	return gin.CustomRecovery(
		func(ctx *gin.Context, err any) {
			ctx.JSON(http.StatusInternalServerError, gouno.InternalServerErrorResponse)
		},
	)
}
