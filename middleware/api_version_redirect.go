package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// LegacyAPIRedirectMiddleware redirects the historically unversioned Gosso API
// routes to their canonical /api/v1 counterparts. It must run before CSRF so
// legacy POST requests reach the redirect rather than being rejected for using
// a path that is intentionally absent from the CSRF bootstrap allowlist.
//
// This is a compatibility redirect, not a second route registration: the
// canonical handler still enforces its own authentication, CSRF and rate limits.
func LegacyAPIRedirectMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if !isLegacyAPIPath(ctx.Request.URL.Path) {
			ctx.Next()
			return
		}

		// EscapedPath keeps encoded path segments intact; the redirect remains
		// relative to this origin and carries the original query unchanged.
		target := "/api/v1" + strings.TrimPrefix(ctx.Request.URL.EscapedPath(), "/api")
		if query := ctx.Request.URL.RawQuery; query != "" {
			target += "?" + query
		}
		ctx.Redirect(http.StatusPermanentRedirect, target)
		ctx.Abort()
	}
}

// isLegacyAPIPath deliberately matches only historical route families.
// Unknown /api paths, /api/v1 paths and future /api/v2 paths must not be
// redirected or silently downgraded to an earlier API contract.
func isLegacyAPIPath(path string) bool {
	switch {
	case strings.HasPrefix(path, "/api/auth/"),
		strings.HasPrefix(path, "/api/admin/"),
		strings.HasPrefix(path, "/api/passkey/"),
		path == "/api/passkeys",
		strings.HasPrefix(path, "/api/passkeys/"),
		path == "/api/oauth2/clients",
		strings.HasPrefix(path, "/api/oauth2/clients/"):
		return true
	default:
		return false
	}
}
