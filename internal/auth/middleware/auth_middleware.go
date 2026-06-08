package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"

	"github.com/rushairer/gosso/internal/audit"
	authService "github.com/rushairer/gosso/internal/auth/service"
	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	tokenService "github.com/rushairer/gosso/internal/token/service"
	"github.com/rushairer/gosso/middleware"
)

// ErrTokenScopeNotAllowed is returned when a scoped token (e.g. MFA token)
// attempts to access a general endpoint that does not permit scoped access.
var ErrTokenScopeNotAllowed = errors.New("token scope not allowed")

// TokenValidator defines the minimal interface for token validation.
type TokenValidator interface {
	ValidateAccessTokenWithContext(ctx context.Context, tokenString string) (*tokenDomain.AccessTokenClaims, error)
}

// ValidateBearerToken extracts and validates the Bearer token from the request.
// Returns the claims on success, or nil with an error on failure.
// This is the shared logic used by both JWTAuthMiddleware and inline authentication in handlers.
func ValidateBearerToken(ctx *gin.Context, tokenSvc TokenValidator, sessionValidator sessionDomain.SessionValidator) (*tokenDomain.AccessTokenClaims, error) {
	tokenString := extractBearerToken(ctx)
	if tokenString == "" {
		return nil, fmt.Errorf("missing authorization")
	}

	claims, err := tokenSvc.ValidateAccessTokenWithContext(ctx.Request.Context(), tokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired token")
	}

	// Reject tokens with non-empty scope (e.g. MFA tokens) from accessing general endpoints
	if claims.Scope != "" {
		return nil, ErrTokenScopeNotAllowed
	}

	// Verify the session still exists (invalidates tokens after account deletion/suspension)
	if sessionValidator != nil && claims.SessionID != "" {
		if _, err := sessionValidator.ValidateSession(ctx.Request.Context(), claims.SessionID); err != nil {
			return nil, fmt.Errorf("session expired or revoked")
		}
	}

	return claims, nil
}

// JWTAuthMiddleware is the JWT authentication middleware.
// sessionValidator is required — it verifies the session still exists in Redis,
// ensuring revoked sessions (e.g. after account deletion or suspension) are rejected.
func JWTAuthMiddleware(tokenSvc *tokenService.TokenService, sessionValidator sessionDomain.SessionValidator) gin.HandlerFunc {
	if sessionValidator == nil {
		panic("JWTAuthMiddleware: sessionValidator must not be nil — session validation is required for security")
	}
	return func(ctx *gin.Context) {
		claims, err := ValidateBearerToken(ctx, tokenSvc, sessionValidator)
		if err != nil {
			status := http.StatusUnauthorized
			if errors.Is(err, ErrTokenScopeNotAllowed) {
				status = http.StatusForbidden
			}
			ctx.AbortWithStatusJSON(status, gouno.NewErrorResponse(status, err.Error()))
			return
		}

		ctx.Set(middleware.ContextKeyAccountID, claims.AccountID)
		ctx.Set(middleware.ContextKeyClaims, claims)
		ctx.Next()
	}
}

func extractBearerToken(ctx *gin.Context) string {
	authHeader := ctx.GetHeader("Authorization")
	if authHeader == "" {
		return ""
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
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
