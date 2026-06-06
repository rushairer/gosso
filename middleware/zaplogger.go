package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// ZapLoggerMiddleware returns a gin.HandlerFunc that logs HTTP requests using zap
// with structured fields including request_id.
func ZapLoggerMiddleware(logger *zap.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		start := time.Now()
		path := ctx.Request.URL.Path
		query := ctx.Request.URL.RawQuery

		ctx.Next()

		latency := time.Since(start)
		status := ctx.Writer.Status()

		fields := []zap.Field{
			zap.Int("status", status),
			zap.String("method", ctx.Request.Method),
			zap.String("path", path),
			zap.String("query", query),
			zap.String("ip", ctx.ClientIP()),
			zap.String("user_agent", ctx.Request.UserAgent()),
			zap.Duration("latency", latency),
			zap.Int("body_size", ctx.Writer.Size()),
		}

		if requestID, exists := ctx.Get(ContextKeyRequestID); exists {
			if rid, ok := requestID.(string); ok && rid != "" {
				fields = append(fields, zap.String("request_id", rid))
			}
		}

		if accountID, exists := ctx.Get(ContextKeyAccountID); exists {
			if aid, ok := accountID.(string); ok && aid != "" {
				fields = append(fields, zap.String("account_id", aid))
			}
		}

		if len(ctx.Errors) > 0 {
			for _, e := range ctx.Errors {
				logger.Error(e.Error(), fields...)
			}
		} else if status >= 500 {
			logger.Error("HTTP", fields...)
		} else if status >= 400 {
			logger.Warn("HTTP", fields...)
		} else {
			logger.Info("HTTP", fields...)
		}
	}
}
