package middleware

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"
	gounoMiddleware "github.com/rushairer/gouno/middleware"
	"go.uber.org/zap"
)

const (
	csrfCookieName       = "csrf_token"
	csrfSecureCookieName = "__Host-csrf_token"
	csrfHeaderName       = "X-CSRF-Token"
	defaultCSRFMaxAge    = 4 * time.Hour
	maxCSRFMaxAge        = 24 * time.Hour
)

// CSRFMiddleware double-submit cookie CSRF protection middleware.
// Skips: Bearer auth, GET/HEAD/OPTIONS, skipPaths exact match.
//
// When secure=true, the cookie uses the __Host- prefix (__Host-csrf_token)
// which enforces Secure, Path=/, and no Domain via the browser.
//
// maxAge controls the CSRF cookie lifetime. If zero, defaults to 4 hours.
// Capped at 24 hours to prevent overly long-lived CSRF tokens.
//
// IMPORTANT: CSRFMiddleware must run BEFORE JWTAuthMiddleware in the middleware chain.
// The Bearer skip relies on the raw Authorization header — if JWTAuthMiddleware
// runs first and strips/rewrites the header, CSRF would be enforced on API calls
// that should be exempt.
func CSRFMiddleware(secure bool, logger *zap.Logger, maxAge time.Duration, skipPaths ...string) gin.HandlerFunc {
	if maxAge <= 0 {
		maxAge = defaultCSRFMaxAge
	}
	if maxAge > maxCSRFMaxAge {
		maxAge = maxCSRFMaxAge
	}

	cookieName := csrfCookieName
	if secure {
		cookieName = csrfSecureCookieName
	}

	return func(ctx *gin.Context) {
		// Skip idempotent methods
		method := ctx.Request.Method
		if method == "GET" || method == "HEAD" || method == "OPTIONS" {
			ensureCSRFCookie(ctx, cookieName, secure, maxAge)
			ctx.Next()
			return
		}

		// Skip Bearer auth (JWT is not affected by CSRF).
		// Validate that the token has plausible JWT format (3 dot-separated segments)
		// to prevent attackers from bypassing CSRF with a garbage "Bearer " prefix.
		// However, if a session cookie is also present, an attacker could use the session
		// cookie for CSRF while the JWT bypasses the check — so only skip when no session
		// cookie coexists with the Bearer token.
		if auth := ctx.GetHeader("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			token := strings.TrimPrefix(auth, "Bearer ")
			if IsPlausibleJWT(token) && hasOnlyAccessTokenCookie(ctx, token) {
				ctx.Next()
				return
			}
		}

		// Skip specified paths (prefix match with path boundary).
		// Uses "/"+ suffix to avoid "/begin" matching "/beginners".
		path := ctx.Request.URL.Path
		for _, sp := range skipPaths {
			if path == sp || strings.HasPrefix(path, sp+"/") {
				ensureCSRFCookie(ctx, cookieName, secure, maxAge)
				ctx.Next()
				return
			}
		}

		// Validate CSRF token
		cookie, err := ctx.Cookie(cookieName)
		if err != nil || cookie == "" {
			ctx.JSON(http.StatusForbidden, gouno.NewErrorResponse(http.StatusForbidden, "CSRF token missing"))
			ctx.Abort()
			return
		}

		// Check header first, then fall back to form field for HTML form submissions
		header := ctx.GetHeader(csrfHeaderName)
		if header == "" {
			header = ctx.PostForm("csrf_token")
		}
		if !gounoMiddleware.CSRFMatches(cookie, header) {
			ctx.JSON(http.StatusForbidden, gouno.NewErrorResponse(http.StatusForbidden, "CSRF token mismatch"))
			ctx.Abort()
			return
		}

		rotateCSRFCookie(ctx, cookieName, secure, logger, maxAge)
		ctx.Next()
	}
}

// ensureCSRFCookie sets the double-submit CSRF cookie, generating a fresh token
// when none is present. Cookie attributes (HttpOnly=false, SameSite=Lax) are
// delegated to the shared gouno primitive.
func ensureCSRFCookie(ctx *gin.Context, cookieName string, secure bool, maxAge time.Duration) {
	if err := gounoMiddleware.EnsureCSRFCookie(ctx, cookieName, secure, maxAge); err != nil {
		ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "internal server error"))
		ctx.Abort()
	}
}

// rotateCSRFCookie generates a new CSRF token and replaces the existing cookie.
// Called after successful validation to prevent token fixation attacks.
// Falls back to keeping the old token if generation fails.
func rotateCSRFCookie(ctx *gin.Context, cookieName string, secure bool, logger *zap.Logger, maxAge time.Duration) {
	newToken, err := gounoMiddleware.GenerateCSRFToken()
	if err != nil {
		logger.Warn("CSRF token rotation failed, keeping old token", zap.Error(err))
		return
	}
	gounoMiddleware.SetCSRFCookie(ctx, cookieName, newToken, secure, maxAge)
}

// IsPlausibleJWT checks if a token has the basic JWT format (three non-empty dot-separated segments),
// validates that the header segment is valid base64url encoding, and verifies the decoded header
// JSON contains an "alg" field (standard in all JOSE headers). This additional check prevents
// arbitrary base64url strings from bypassing CSRF protection.
// Exported for use by other packages that need to validate Bearer token format (e.g. CSRF bypass checks).
func IsPlausibleJWT(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(parts[0]) == 0 || len(parts[1]) == 0 || len(parts[2]) == 0 {
		return false
	}
	// Validate the header segment is valid base64url encoding
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	// Verify the header contains an "alg" field — present in all standard JWT/JOSE headers.
	// This prevents arbitrary base64url strings (e.g. "aaaa.bbbb.cccc") from bypassing CSRF.
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil || header.Alg == "" {
		return false
	}
	return true
}

// sessionCookieNames is the fixed allowlist used when deciding whether a
// request mixes a session cookie with Bearer authentication. A fixed set avoids
// false positives from unrelated cookies such as analytics_session_id.
var sessionCookieNames = []string{
	"session",
	"session_id",
	"gosso_session",
	"gosso_session_id",
}

func hasOnlyAccessTokenCookie(ctx *gin.Context, bearerToken string) bool {
	hasSession := false
	hasAccessCookie := false
	matches := false

	for _, c := range ctx.Request.Cookies() {
		name := strings.ToLower(c.Name)
		isSession := false
		for _, sn := range sessionCookieNames {
			if name == sn {
				isSession = true
				break
			}
		}
		if isSession || strings.HasSuffix(name, "_session_id") || strings.HasSuffix(name, "-session-id") {
			hasSession = true
		}

		if name == "access_token" || name == "__secure-access_token" || name == "__host-access_token" {
			hasAccessCookie = true
			if c.Value == bearerToken {
				matches = true
			}
		}
	}

	if hasSession {
		return false
	}
	if hasAccessCookie {
		return matches
	}
	return true
}
