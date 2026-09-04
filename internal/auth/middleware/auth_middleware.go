package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rushairer/gouno"

	"github.com/rushairer/gosso/internal/audit"
	authService "github.com/rushairer/gosso/internal/auth/service"
	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	"github.com/rushairer/gosso/middleware"
)

// ErrTokenScopeNotAllowed is returned when a scoped token (e.g. MFA token)
// attempts to access a general endpoint that does not permit scoped access.
var ErrTokenScopeNotAllowed = errors.New("token scope not allowed")

// TokenValidator defines the minimal interface for token validation.
type TokenValidator interface {
	ValidateAccessTokenWithContext(ctx context.Context, tokenString string) (*tokenDomain.AccessTokenClaims, error)
}

// errUnauthorized is the generic error returned for all authentication failures.
// Detailed reasons are logged server-side only to prevent information leakage.
var errUnauthorized = errors.New("unauthorized")

// AuthConfigOptions holds configuration options for the JWT auth middleware.
type AuthConfigOptions struct {
	LoginURL           string
	EnableCookieAuth   bool
	AuthCookieName     string
	SessionCookieName  string
	AccountInfoFetcher AccountInfoFetcher
}

// AccountInfoFetcher retrieves account information (roles, permissions, etc.)
// from a session's account ID. This is used by the opaque session cookie
// authentication path to reconstruct claims without a bearer token.
type AccountInfoFetcher interface {
	FetchAccountInfo(ctx context.Context, accountID string) (*AccountInfo, error)
}

// AccountInfo holds the data needed to reconstruct claims from a session.
type AccountInfo struct {
	AccountID   string
	Username    string
	Email       string
	Roles       []string
	Permissions []string
}

// ValidateBearerToken extracts and validates the Bearer token from the request.
// Returns the claims on success, or nil with an error on failure.
// This is the shared logic used by both JWTAuthMiddleware and inline authentication in handlers.
func ValidateBearerToken(ctx *gin.Context, tokenSvc TokenValidator, sessionValidator sessionDomain.SessionValidator) (*tokenDomain.AccessTokenClaims, error) {
	return ValidateBearerTokenWithConfig(ctx, tokenSvc, sessionValidator, AuthConfigOptions{
		EnableCookieAuth:  true,
		AuthCookieName:    "__Host-access_token",
		SessionCookieName: "__Host-gosso-session",
	})
}

// ValidateBearerTokenWithConfig validates token with specific config options.
func ValidateBearerTokenWithConfig(ctx *gin.Context, tokenSvc TokenValidator, sessionValidator sessionDomain.SessionValidator, cfg AuthConfigOptions) (*tokenDomain.AccessTokenClaims, error) {
	// First try: Bearer token or legacy token cookie (for non-browser API clients)
	tokenString := extractBearerTokenWithConfig(ctx, cfg.EnableCookieAuth, cfg.AuthCookieName)
	if tokenString != "" {
		claims, err := tokenSvc.ValidateAccessTokenWithContext(ctx.Request.Context(), tokenString)
		if err != nil {
			return nil, errUnauthorized
		}

		// Reject internal MFA tokens from accessing general endpoints.
		if claims.Scope == authService.ScopeMFA {
			return nil, ErrTokenScopeNotAllowed
		}

		// Verify the session still exists.
		if claims.SessionID != "" {
			if sessionValidator == nil {
				return nil, errUnauthorized
			}
			session, err := sessionValidator.ValidateSession(ctx.Request.Context(), claims.SessionID)
			if err != nil {
				return nil, errUnauthorized
			}
			ctx.Set(middleware.ContextKeySession, session)
		}

		return claims, nil
	}

	// Second try: opaque SSO session cookie (browser SPA path).
	// This replaces the old token-cookie fallback for browser requests.
	// The cookie value is an opaque session ID, NOT a bearer token.
	if cfg.SessionCookieName != "" && sessionValidator != nil {
		cookieSID := ""
		if cookie, err := ctx.Cookie(cfg.SessionCookieName); err == nil && cookie != "" {
			cookieSID = cookie
		}
		if cookieSID != "" {
			session, err := sessionValidator.ValidateSession(ctx.Request.Context(), cookieSID)
			if err != nil {
				return nil, errUnauthorized
			}
			ctx.Set(middleware.ContextKeySession, session)

			// Reconstruct claims from the session + account info.
			// No JWT is issued; the claims are server-side only.
			claims := &tokenDomain.AccessTokenClaims{
				RegisteredClaims: jwt.RegisteredClaims{Audience: jwt.ClaimStrings{"urn:gouno:gosso-api"}},
				AccountID:        session.AccountID,
				Username:         session.Username,
				SessionID:        session.ID,
				Scope:            "openid profile email",
			}
			if authTime := session.AuthenticationTime(); !authTime.IsZero() {
				unix := authTime.Unix()
				claims.AuthTime = &unix
			}
			if len(session.AuthMethods) > 0 {
				claims.AMR = append([]string(nil), session.AuthMethods...)
			}
			// Fetch roles/permissions from the account service if available.
			if cfg.AccountInfoFetcher != nil {
				if info, err := cfg.AccountInfoFetcher.FetchAccountInfo(ctx.Request.Context(), session.AccountID); err == nil && info != nil {
					claims.Roles = info.Roles
					claims.Permissions = info.Permissions
					if info.Email != "" {
						claims.Email = info.Email
					}
					if hasRole(info.Roles, authService.RoleAdmin) {
						claims.Scope += " " + authService.ScopeAdmin
					}
				}
			}
			return claims, nil
		}
	}

	return nil, errUnauthorized
}

// JWTAuthMiddleware is the JWT authentication middleware.
// sessionValidator is required — it verifies the session still exists in Redis,
// ensuring revoked sessions (e.g. after account deletion or suspension) are rejected.
// Returns an error if sessionValidator is nil.
func JWTAuthMiddleware(tokenSvc TokenValidator, sessionValidator sessionDomain.SessionValidator) (gin.HandlerFunc, error) {
	return JWTAuthMiddlewareWithConfig(tokenSvc, sessionValidator, AuthConfigOptions{
		LoginURL:          "/login",
		EnableCookieAuth:  true,
		AuthCookieName:    "__Host-access_token",
		SessionCookieName: "__Host-gosso-session",
	})
}

// JWTAuthMiddlewareWithConfig creates the middleware with custom config options.
func JWTAuthMiddlewareWithConfig(tokenSvc TokenValidator, sessionValidator sessionDomain.SessionValidator, cfg AuthConfigOptions) (gin.HandlerFunc, error) {
	if sessionValidator == nil {
		return nil, fmt.Errorf("JWTAuthMiddleware: sessionValidator must not be nil — session validation is required for security")
	}
	return func(ctx *gin.Context) {
		claims, err := ValidateBearerTokenWithConfig(ctx, tokenSvc, sessionValidator, cfg)
		if err != nil {
			// If it's a browser request to /oauth2/authorize, redirect to the custom login page!
			if ctx.Request.Method == "GET" && strings.HasPrefix(ctx.Request.URL.Path, "/oauth2/authorize") {
				loginURL := cfg.LoginURL
				if loginURL == "" {
					loginURL = "/login"
				}
				redirectURL := loginURL
				if strings.Contains(redirectURL, "?") {
					redirectURL += "&redirect_uri=" + url.QueryEscape(ctx.Request.RequestURI)
				} else {
					redirectURL += "?redirect_uri=" + url.QueryEscape(ctx.Request.RequestURI)
				}
				ctx.Redirect(http.StatusFound, redirectURL)
				ctx.Abort()
				return
			}

			status := http.StatusUnauthorized
			msg := "unauthorized"
			if errors.Is(err, ErrTokenScopeNotAllowed) {
				status = http.StatusForbidden
				msg = "forbidden"
			}
			ctx.AbortWithStatusJSON(status, gouno.NewErrorResponse(status, msg))
			return
		}

		ctx.Set(middleware.ContextKeyAccountID, claims.AccountID)
		ctx.Set(middleware.ContextKeyClaims, claims)
		ctx.Next()
	}, nil
}

func extractBearerToken(ctx *gin.Context) string {
	return extractBearerTokenWithConfig(ctx, true, "__Host-access_token")
}

func extractBearerTokenWithConfig(ctx *gin.Context, enableCookieAuth bool, authCookieName string) string {
	authHeader := ctx.GetHeader("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			return parts[1]
		}
	}
	// Fallback to access_token cookie if enabled
	if enableCookieAuth && authCookieName != "" {
		if cookie, err := ctx.Cookie(authCookieName); err == nil {
			return cookie
		}
		if !strings.HasPrefix(authCookieName, "__Secure-") && !strings.HasPrefix(authCookieName, "__Host-") {
			if cookie, err := ctx.Cookie("__Secure-" + authCookieName); err == nil {
				return cookie
			}
		}
	}
	return ""
}

// AdminRequiredMiddleware checks for admin role (must be used after JWTAuthMiddleware)
func AdminRequiredMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		claimsRaw, exists := ctx.Get(middleware.ContextKeyClaims)
		if !exists {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "missing authorization"))
			return
		}

		claims, ok := claimsRaw.(*tokenDomain.AccessTokenClaims)
		if !ok {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "invalid claims type"))
			return
		}

		if !hasScope(claims.Scope, authService.ScopeAdmin) {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gouno.NewErrorResponse(http.StatusForbidden, "admin client scope required"))
			return
		}

		if !hasRole(claims.Roles, authService.RoleAdmin) {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gouno.NewErrorResponse(http.StatusForbidden, "admin access required"))
			return
		}

		ctx.Next()
	}
}

// RequirePermission enforces one fine-grained admin permission after
// AdminRequiredMiddleware. The admin:* wildcard is reserved for break-glass and
// initial administrator roles.
func RequirePermission(required string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		claimsRaw, exists := ctx.Get(middleware.ContextKeyClaims)
		if !exists {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "missing authorization"))
			return
		}
		claims, ok := claimsRaw.(*tokenDomain.AccessTokenClaims)
		if !ok {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gouno.NewErrorResponse(http.StatusInternalServerError, "invalid claims type"))
			return
		}
		if !hasPermission(claims.Permissions, required) {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gouno.NewErrorResponse(http.StatusForbidden, "insufficient admin permission"))
			return
		}
		ctx.Next()
	}
}

func hasPermission(permissions []string, required string) bool {
	for _, permission := range permissions {
		if permission == "admin:*" || permission == required {
			return true
		}
	}
	return false
}

func hasRole(roles []string, required string) bool {
	for _, role := range roles {
		if role == required {
			return true
		}
	}
	return false
}

func hasScope(scopeClaim, required string) bool {
	for _, scope := range strings.Fields(scopeClaim) {
		if scope == required {
			return true
		}
	}
	return false
}

// AuditMetadataMiddleware stores client IP, user agent, and request ID in request context for audit logging.
func AuditMetadataMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var requestIDStr string
		if v, ok := ctx.Get("request_id"); ok {
			requestIDStr, _ = v.(string)
		}
		ctx.Request = ctx.Request.WithContext(
			audit.SetMetadata(ctx.Request.Context(), ctx.ClientIP(), ctx.Request.UserAgent(), requestIDStr),
		)
		ctx.Next()
	}
}
