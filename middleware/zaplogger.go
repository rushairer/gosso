package middleware

import (
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// sensitiveQueryParams are query parameter names whose values should be redacted in logs.
var sensitiveQueryParams = map[string]bool{
	"token":         true,
	"code":          true,
	"code_verifier": true,
	"client_secret": true,
	"password":      true,
	"refresh_token": true,
	"access_token":  true,
	"id_token":      true,
}

// maxUserAgentLen is the maximum length of the User-Agent string logged.
// Prevents log inflation attacks where an attacker sends very long User-Agent headers.
const maxUserAgentLen = 512

// truncateString truncates a string to maxLen characters, appending "..." if truncated.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "...(truncated)"
}

// sanitizeQuery replaces sensitive query parameter values with [REDACTED].
func sanitizeQuery(raw string) string {
	if raw == "" {
		return ""
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return "[PARSE_ERROR]"
	}
	for key := range values {
		if sensitiveQueryParams[strings.ToLower(key)] {
			values.Set(key, "[REDACTED]")
		}
	}
	return values.Encode()
}

// ZapLoggerMiddleware returns a gin.HandlerFunc that logs HTTP requests using zap
// with structured fields including request_id.
// Note: this middleware does not log response headers, so CSRF tokens (X-CSRF-Token)
// and other sensitive response data are never exposed in logs.
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
			zap.String("query", sanitizeQuery(query)),
			zap.String("ip", ctx.ClientIP()),
			zap.String("user_agent", truncateString(ctx.Request.UserAgent(), maxUserAgentLen)),
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
