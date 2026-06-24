package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
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
	LoginURL         string
	EnableCookieAuth bool
	AuthCookieName   string
}

// ValidateBearerToken extracts and validates the Bearer token from the request.
// Returns the claims on success, or nil with an error on failure.
// This is the shared logic used by both JWTAuthMiddleware and inline authentication in handlers.
func ValidateBearerToken(ctx *gin.Context, tokenSvc TokenValidator, sessionValidator sessionDomain.SessionValidator) (*tokenDomain.AccessTokenClaims, error) {
	return ValidateBearerTokenWithConfig(ctx, tokenSvc, sessionValidator, AuthConfigOptions{
		EnableCookieAuth: true,
		AuthCookieName:   "access_token",
	})
}

// ValidateBearerTokenWithConfig validates token with specific config options.
func ValidateBearerTokenWithConfig(ctx *gin.Context, tokenSvc TokenValidator, sessionValidator sessionDomain.SessionValidator, cfg AuthConfigOptions) (*tokenDomain.AccessTokenClaims, error) {
	tokenString := extractBearerTokenWithConfig(ctx, cfg.EnableCookieAuth, cfg.AuthCookieName)
	if tokenString == "" {
		return nil, errUnauthorized
	}

	claims, err := tokenSvc.ValidateAccessTokenWithContext(ctx.Request.Context(), tokenString)
	if err != nil {
		return nil, errUnauthorized
	}

	// Reject internal MFA tokens from accessing general endpoints. OAuth/OIDC
	// access tokens use normal scope strings such as "openid profile" and must
	// remain valid for resource endpoints like /oidc/userinfo.
	if claims.Scope == authService.ScopeMFA {
		return nil, ErrTokenScopeNotAllowed
	}

	// Verify the session still exists (invalidates tokens after account deletion/suspension).
	// If sessionValidator is nil but the token has a SessionID, reject to prevent bypass.
	if claims.SessionID != "" {
		if sessionValidator == nil {
			return nil, errUnauthorized
		}
		if _, err := sessionValidator.ValidateSession(ctx.Request.Context(), claims.SessionID); err != nil {
			return nil, errUnauthorized
		}
	}

	return claims, nil
}

// JWTAuthMiddleware is the JWT authentication middleware.
// sessionValidator is required — it verifies the session still exists in Redis,
// ensuring revoked sessions (e.g. after account deletion or suspension) are rejected.
// Returns an error if sessionValidator is nil.
func JWTAuthMiddleware(tokenSvc TokenValidator, sessionValidator sessionDomain.SessionValidator) (gin.HandlerFunc, error) {
	return JWTAuthMiddlewareWithConfig(tokenSvc, sessionValidator, AuthConfigOptions{
		LoginURL:         "/login",
		EnableCookieAuth: true,
		AuthCookieName:   "access_token",
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
	return extractBearerTokenWithConfig(ctx, true, "access_token")
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

		for _, role := range claims.Roles {
			if role == authService.RoleAdmin {
				ctx.Next()
				return
			}
		}

		ctx.AbortWithStatusJSON(http.StatusForbidden, gouno.NewErrorResponse(http.StatusForbidden, "admin access required"))
	}
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
