package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"
	"go.uber.org/zap"
)

const (
	csrfCookieName       = "csrf_token"
	csrfSecureCookieName = "__Host-csrf_token"
	csrfHeaderName       = "X-CSRF-Token"
	csrfTokenLen         = 32
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
			setCSRFCookie(ctx, cookieName, secure, maxAge)
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
			if IsPlausibleJWT(strings.TrimPrefix(auth, "Bearer ")) && !hasSessionCookie(ctx) {
				ctx.Next()
				return
			}
		}

		// Skip specified paths (prefix match with path boundary).
		// Uses "/"+ suffix to avoid "/begin" matching "/beginners".
		path := ctx.Request.URL.Path
		for _, sp := range skipPaths {
			if path == sp || strings.HasPrefix(path, sp+"/") {
				setCSRFCookie(ctx, cookieName, secure, maxAge)
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
		if header == "" || subtle.ConstantTimeCompare([]byte(header), []byte(cookie)) != 1 {
			ctx.JSON(http.StatusForbidden, gouno.NewErrorResponse(http.StatusForbidden, "CSRF token mismatch"))
			ctx.Abort()
			return
		}

		rotateCSRFCookie(ctx, cookieName, secure, logger, maxAge)
		ctx.Next()
	}
}

// setCSRFCookie sets the CSRF token cookie (generates one if absent).
func setCSRFCookie(ctx *gin.Context, cookieName string, secure bool, maxAge time.Duration) {
	cookie, _ := ctx.Cookie(cookieName)
	if cookie == "" {
		var err error
		cookie, err = generateCSRFToken()
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "internal server error"))
			ctx.Abort()
			return
		}
	}

	http.SetCookie(ctx.Writer, &http.Cookie{
		Name:     cookieName,
		Value:    cookie,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		HttpOnly: false, // JS needs to read it (required for double-submit cookie pattern)
		Secure:   secure,
		// SameSiteLaxMode is required for OAuth2 redirect callbacks (top-level
		// navigations from external identity providers). Strict would block the
		// CSRF cookie on those cross-site redirects, breaking the OAuth flow.
		// Bearer-token API calls skip CSRF entirely (see CSRFMiddleware), so
		// Lax provides sufficient protection for cookie-based form submissions.
		SameSite: http.SameSiteLaxMode,
	})

	// Do NOT return the CSRF token in a response header. SPAs should read it
	// directly from the cookie (HttpOnly=false is required for double-submit cookie).
}

// rotateCSRFCookie generates a new CSRF token and replaces the existing cookie.
// Called after successful validation to prevent token fixation attacks.
// Falls back to keeping the old token if generation fails.
func rotateCSRFCookie(ctx *gin.Context, cookieName string, secure bool, logger *zap.Logger, maxAge time.Duration) {
	newToken, err := generateCSRFToken()
	if err != nil {
		logger.Warn("CSRF token rotation failed, keeping old token", zap.Error(err))
		return
	}

	http.SetCookie(ctx.Writer, &http.Cookie{
		Name:     cookieName,
		Value:    newToken,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode, // See setCSRFCookie for rationale
	})
	// Do NOT return the rotated token in a response header — SPAs read from cookie.
}

// generateCSRFToken generates a cryptographically secure random CSRF token.
func generateCSRFToken() (string, error) {
	b := make([]byte, csrfTokenLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate csrf token: %w", err)
	}
	return hex.EncodeToString(b), nil
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

// hasSessionCookie checks whether the request contains a cookie that looks like
// a session cookie. This prevents the Bearer-token CSRF bypass from being
// exploited when a session cookie is also present (the attacker could use the
// session cookie for CSRF while the JWT satisfies the bypass check).
//
// The function checks for the application-specific CSRF cookie names and common
// session cookie patterns. Using a fixed set avoids false positives from
// unrelated cookies (e.g., analytics_session_id) that could incorrectly force
// CSRF validation on a pure Bearer-token request.
var sessionCookieNames = []string{
	"session",
	"session_id",
	"gosso_session",
	"gosso_session_id",
}

func hasSessionCookie(ctx *gin.Context) bool {
	for _, c := range ctx.Request.Cookies() {
		name := strings.ToLower(c.Name)
		for _, sn := range sessionCookieNames {
			if name == sn {
				return true
			}
		}
		// Also match common patterns: *_session_id, *-sid (but not substrings like "ads_sid")
		if strings.HasSuffix(name, "_session_id") || strings.HasSuffix(name, "-session-id") {
			return true
		}
	}
	return false
}
