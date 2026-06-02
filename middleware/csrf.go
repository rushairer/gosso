package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	csrfCookieName = "csrf_token"
	csrfHeaderName = "X-CSRF-Token"
	csrfTokenLen   = 32
)

// CSRFMiddleware double-submit cookie CSRF protection middleware.
// Skips: Bearer auth, GET/HEAD/OPTIONS, skipPaths prefix match.
func CSRFMiddleware(secure bool, skipPaths ...string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Skip idempotent methods
		method := ctx.Request.Method
		if method == "GET" || method == "HEAD" || method == "OPTIONS" {
			setCSRFCookie(ctx, secure)
			ctx.Next()
			return
		}

		// Skip Bearer auth (JWT is not affected by CSRF)
		if strings.HasPrefix(ctx.GetHeader("Authorization"), "Bearer ") {
			setCSRFCookie(ctx, secure)
			ctx.Next()
			return
		}

		// Skip specified paths
		path := ctx.Request.URL.Path
		for _, sp := range skipPaths {
			if strings.HasPrefix(path, sp) {
				setCSRFCookie(ctx, secure)
				ctx.Next()
				return
			}
		}

		// Validate CSRF token
		cookie, err := ctx.Cookie(csrfCookieName)
		if err != nil || cookie == "" {
			ctx.JSON(http.StatusForbidden, gin.H{
				"code":    403,
				"message": "CSRF token missing",
			})
			ctx.Abort()
			return
		}

		header := ctx.GetHeader(csrfHeaderName)
		if header == "" || header != cookie {
			ctx.JSON(http.StatusForbidden, gin.H{
				"code":    403,
				"message": "CSRF token mismatch",
			})
			ctx.Abort()
			return
		}

		setCSRFCookie(ctx, secure)
		ctx.Next()
	}
}

// setCSRFCookie sets the CSRF token cookie (generates one if absent).
func setCSRFCookie(ctx *gin.Context, secure bool) {
	cookie, _ := ctx.Cookie(csrfCookieName)
	if cookie == "" {
		cookie = generateCSRFToken()
	}

	http.SetCookie(ctx.Writer, &http.Cookie{
		Name:     csrfCookieName,
		Value:    cookie,
		Path:     "/",
		MaxAge:   int((4 * time.Hour).Seconds()),
		HttpOnly: false, // JS needs to read it
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})

	// Also return in response header for SPA consumption
	ctx.Header(csrfHeaderName, cookie)
}

// generateCSRFToken generates a cryptographically secure random CSRF token.
func generateCSRFToken() string {
	b := make([]byte, csrfTokenLen)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
