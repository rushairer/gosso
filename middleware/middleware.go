package middleware

import (
	"errors"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/gin-contrib/timeout"
	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"
	gounoMiddleware "github.com/rushairer/gouno/middleware"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/utility"
)

// TimeoutMiddleware returns a Gin handler that aborts with 408 when a request
// exceeds the given duration.
func TimeoutMiddleware(requestTimeout time.Duration) gin.HandlerFunc {
	return timeout.New(
		timeout.WithTimeout(requestTimeout),
		timeout.WithResponse(
			func(ctx *gin.Context) {
				ctx.JSON(http.StatusRequestTimeout, gouno.NewRequestTimeoutResponse())
			},
		),
	)
}

// RecoveryMiddleware returns a Gin handler that recovers from panics, logs the
// stack trace, and responds with 500.
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
			ctx.JSON(http.StatusInternalServerError, gouno.NewInternalServerErrorResponse())
		},
	)
}

// SecurityHeadersMiddleware sets common security response headers.
// HSTS is only set when isProduction is true (meaningless over plain HTTP).
// A per-request CSP nonce is generated and stored in the Gin context for use in templates.
// The shared static headers are delegated to the gouno framework.
func SecurityHeadersMiddleware(isProduction bool) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		nonce, err := gounoMiddleware.GenerateCSPNonce()
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gouno.NewInternalServerErrorResponse())
			return
		}
		ctx.Set(cspNonceKey, nonce)

		csp := "default-src 'self'; script-src 'self' 'nonce-" + nonce + "'; style-src 'self' 'nonce-" + nonce + "'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
		if isProduction {
			csp += "; upgrade-insecure-requests"
		}

		gounoMiddleware.SecurityHeaders(gounoMiddleware.SecurityHeadersOptions{
			IsProduction:              isProduction,
			CSP:                       csp,
			PermissionsPolicy:         "geolocation=(), camera=(), microphone=(), payment=(), usb=(), midi=(), autoplay=(), fullscreen=()",
			CrossOriginOpenerPolicy:   "same-origin",
			CrossOriginResourcePolicy: "same-origin",
		})(ctx)
	}
}

const cspNonceKey = "csp_nonce"

// GetCSPNonce returns the CSP nonce for the current request, or an empty string if not set.
func GetCSPNonce(ctx *gin.Context) string {
	if v, ok := ctx.Get(cspNonceKey); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// MaxBodySizeMiddleware limits the request body to the given number of bytes.
// Returns 413 Request Entity Too Large if the limit is exceeded.
func MaxBodySizeMiddleware(maxBytes int64) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Request.Body = http.MaxBytesReader(ctx.Writer, ctx.Request.Body, maxBytes)
		ctx.Next()

		// After handlers have run, check if any error is a MaxBytesError
		// and rewrite the response to 413.
		for _, ginErr := range ctx.Errors {
			var maxBytesErr *http.MaxBytesError
			if ginErr.Err != nil && errors.As(ginErr.Err, &maxBytesErr) {
				if !ctx.Writer.Written() {
					ctx.JSON(http.StatusRequestEntityTooLarge, gouno.NewErrorResponse(http.StatusRequestEntityTooLarge, "request body too large"))
				}
				return
			}
		}
	}
}
