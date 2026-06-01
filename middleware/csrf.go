package middleware

import (
	"crypto/rand"
	"encoding/hex"
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

// CSRFMiddleware 双提交 Cookie CSRF 防护中间件
// 跳过条件：Bearer auth、GET/HEAD/OPTIONS、skipPaths 前缀匹配
func CSRFMiddleware(secure bool, skipPaths ...string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// 跳过幂等方法
		method := ctx.Request.Method
		if method == "GET" || method == "HEAD" || method == "OPTIONS" {
			setCSRFCookie(ctx, secure)
			ctx.Next()
			return
		}

		// 跳过 Bearer auth（JWT 不受 CSRF 影响）
		if strings.HasPrefix(ctx.GetHeader("Authorization"), "Bearer ") {
			setCSRFCookie(ctx, secure)
			ctx.Next()
			return
		}

		// 跳过指定路径
		path := ctx.Request.URL.Path
		for _, sp := range skipPaths {
			if strings.HasPrefix(path, sp) {
				setCSRFCookie(ctx, secure)
				ctx.Next()
				return
			}
		}

		// 验证 CSRF token
		cookie, err := ctx.Cookie(csrfCookieName)
		if err != nil || cookie == "" {
			ctx.JSON(http.StatusForbidden, gin.H{
				"code":    403,
				"message": "CSRF token missing",
			})
			ctx.Abort()
			return
		}

		header := ctx.GetHeader(csrfHeaderName)
		if header == "" || header != cookie {
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

// setCSRFCookie 设置 CSRF token cookie（如不存在则生成）
func setCSRFCookie(ctx *gin.Context, secure bool) {
	cookie, _ := ctx.Cookie(csrfCookieName)
	if cookie == "" {
		cookie = generateCSRFToken()
	}

	ctx.SetCookie(
		csrfCookieName,
		cookie,
		int((4 * time.Hour).Seconds()), // 4 hours
		"/",
		"",
		secure,
		false, // HttpOnly=false so JS can read it
	)

	// 同时在 response header 中返回，方便 SPA 读取
	ctx.Header(csrfHeaderName, cookie)
}

// generateCSRFToken 生成加密安全的随机 CSRF token
func generateCSRFToken() string {
	b := make([]byte, csrfTokenLen)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
