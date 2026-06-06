package middleware

import (
	"net/http"
	"runtime/debug"
	"time"

	"github.com/gin-contrib/timeout"
	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/utility"
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
	logger = utility.EnsureLogger(logger)
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

// SecurityHeadersMiddleware sets common security response headers.
// HSTS is only set when isProduction is true (meaningless over plain HTTP).
func SecurityHeadersMiddleware(isProduction bool) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Header("X-Content-Type-Options", "nosniff")
		ctx.Header("X-Frame-Options", "DENY")
		ctx.Header("X-XSS-Protection", "0")
		ctx.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		if isProduction {
			ctx.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}
		ctx.Header("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
		ctx.Header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'")
		ctx.Header("Cross-Origin-Opener-Policy", "same-origin")
		ctx.Header("Cross-Origin-Resource-Policy", "same-origin")
		ctx.Next()
	}
}

// MaxBodySizeMiddleware limits the request body to the given number of bytes.
// Returns 413 Request Entity Too Large if the limit is exceeded.
func MaxBodySizeMiddleware(maxBytes int64) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Request.Body = http.MaxBytesReader(ctx.Writer, ctx.Request.Body, maxBytes)
		ctx.Next()
	}
}
