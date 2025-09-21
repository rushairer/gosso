package middleware

import (
	"gosso/internal/context"
	"gosso/internal/service"

	"github.com/gin-gonic/gin"
)

func AuthMiddleware(authService *service.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			c.JSON(401, gin.H{"error": "missing token"})
			c.Abort()
			return
		}

		// 验证 token
		authInfo, err := authService.ValidateToken(token)
		if err != nil {
			c.JSON(401, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		// 存储认证信息到 context
		ctx := context.WithAuthInfo(c.Request.Context(), authInfo)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}
