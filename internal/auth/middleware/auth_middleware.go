package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gosso/internal/audit"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	tokenService "github.com/rushairer/gosso/internal/token/service"
	"github.com/rushairer/gouno"
)

const (
	// ContextKeyAccountID 存储在 gin.Context 中的账号 ID
	ContextKeyAccountID = "account_id"
	// ContextKeyClaims 存储在 gin.Context 中的 JWT Claims
	ContextKeyClaims = "jwt_claims"
)

// JWTAuthMiddleware JWT 认证中间件
func JWTAuthMiddleware(tokenSvc *tokenService.TokenService) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		tokenString := extractBearerToken(ctx)
		if tokenString == "" {
			// 回退到 query/form 参数（支持 HTML 表单提交）
			tokenString = ctx.Query("access_token")
			if tokenString == "" {
				tokenString = ctx.PostForm("access_token")
			}
		}
		if tokenString == "" {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "missing authorization"))
			return
		}

		claims, err := tokenSvc.ValidateAccessToken(tokenString)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gouno.NewErrorResponse(http.StatusUnauthorized, "invalid or expired token"))
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

// AdminRequiredMiddleware 管理员角色检查中间件（需在 JWTAuthMiddleware 之后使用）
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

// AuditMetadataMiddleware stores client IP and user agent in request context for audit logging.
func AuditMetadataMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Request = ctx.Request.WithContext(
			audit.SetMetadata(ctx.Request.Context(), ctx.ClientIP(), ctx.Request.UserAgent()),
		)
		ctx.Next()
	}
}
