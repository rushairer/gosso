package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
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
// Skips: Bearer auth, GET/HEAD/OPTIONS, skipPaths exact match.
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

		// Skip specified paths (exact match)
		path := ctx.Request.URL.Path
		for _, sp := range skipPaths {
			if path == sp {
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

		// Check header first, then fall back to form field for HTML form submissions
		header := ctx.GetHeader(csrfHeaderName)
		if header == "" {
			header = ctx.PostForm("csrf_token")
		}
		if header == "" || subtle.ConstantTimeCompare([]byte(header), []byte(cookie)) != 1 {
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
		var err error
		cookie, err = generateCSRFToken()
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			ctx.Abort()
			return
		}
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
func generateCSRFToken() (string, error) {
	b := make([]byte, csrfTokenLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate csrf token: %w", err)
	}
	return hex.EncodeToString(b), nil
}
