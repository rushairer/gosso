package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"

	"github.com/rushairer/gosso/internal/audit"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	tokenService "github.com/rushairer/gosso/internal/token/service"
)

const (
	// ContextKeyAccountID stores the account ID in gin.Context
	ContextKeyAccountID = "account_id"
	// ContextKeyClaims stores the JWT claims in gin.Context
	ContextKeyClaims = "jwt_claims"
)

// JWTAuthMiddleware is the JWT authentication middleware
func JWTAuthMiddleware(tokenSvc *tokenService.TokenService) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		tokenString := extractBearerToken(ctx)
		if tokenString == "" {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "missing authorization"))
			return
		}

		claims, err := tokenSvc.ValidateAccessTokenWithContext(ctx.Request.Context(), tokenString)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "invalid or expired token"))
			return
		}

		// Reject tokens with non-empty scope (e.g. MFA tokens) from accessing general endpoints
		if claims.Scope != "" {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gouno.NewErrorResponse(http.StatusForbidden, "token scope not allowed"))
			return
		}

		ctx.Set(ContextKeyAccountID, claims.AccountID)
		ctx.Set(ContextKeyClaims, claims)
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
		claimsRaw, exists := ctx.Get(ContextKeyClaims)
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
			if role == "admin" {
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
		requestID, _ := ctx.Get("request_id")
		requestIDStr, _ := requestID.(string)
		ctx.Request = ctx.Request.WithContext(
			audit.SetMetadata(ctx.Request.Context(), ctx.ClientIP(), ctx.Request.UserAgent(), requestIDStr),
		)
		ctx.Next()
	}
}
