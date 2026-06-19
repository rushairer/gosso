package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/gin-contrib/timeout"
	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"
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
func SecurityHeadersMiddleware(isProduction bool) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		nonce, err := generateCSPNonce()
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gouno.NewInternalServerErrorResponse())
			return
		}
		ctx.Set(cspNonceKey, nonce)

		ctx.Header("X-Content-Type-Options", "nosniff")
		ctx.Header("X-Frame-Options", "DENY")
		ctx.Header("X-XSS-Protection", "0")
		ctx.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		if isProduction {
			ctx.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}
		ctx.Header("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=(), usb=(), midi=(), autoplay=(), fullscreen=()")
		ctx.Header("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'nonce-"+nonce+"'; style-src 'self' 'nonce-"+nonce+"'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests; frame-ancestors 'none'")
		ctx.Header("Cross-Origin-Opener-Policy", "same-origin")
		ctx.Header("Cross-Origin-Resource-Policy", "same-origin")
		ctx.Next()
	}
}

const (
	cspNonceKey  = "csp_nonce"
	cspNonceSize = 16
)

// GetCSPNonce returns the CSP nonce for the current request, or an empty string if not set.
func GetCSPNonce(ctx *gin.Context) string {
	if v, ok := ctx.Get(cspNonceKey); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func generateCSPNonce() (string, error) {
	b := make([]byte, cspNonceSize)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// MaxBodySizeMiddleware limits the request body to the given number of bytes.
// Returns 413 Request Entity Too Large if the limit is exceeded.
func MaxBodySizeMiddleware(maxBytes int64) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Request.Body = http.MaxBytesReader(ctx.Writer, ctx.Request.Body, maxBytes)
		ctx.Next()
	}
}
