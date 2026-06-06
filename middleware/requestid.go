package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	// ContextKeyRequestID is the gin context key for the request ID.
	ContextKeyRequestID = "request_id"
	// HeaderRequestID is the HTTP header name for the request ID.
	HeaderRequestID = "X-Request-ID"
	// ContextKeyAccountID is the gin context key for the account ID.
	ContextKeyAccountID = "account_id"

	maxRequestIDLength = 128
)

// RequestIDMiddleware injects a unique request ID into every request.
// If the incoming request already has an X-Request-ID header, it is preserved;
// otherwise a new UUID is generated.
func RequestIDMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		requestID := ctx.GetHeader(HeaderRequestID)
		if requestID == "" {
			requestID = uuid.New().String()
		} else if len(requestID) > maxRequestIDLength || !isValidRequestID(requestID) {
			requestID = uuid.New().String()
		}

		ctx.Set(ContextKeyRequestID, requestID)
		ctx.Header(HeaderRequestID, requestID)

		ctx.Next()
	}
}

// isValidRequestID checks that the request ID contains only safe ASCII characters.
func isValidRequestID(s string) bool {
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' && r != '.' {
			return false
		}
	}
	return true
}
