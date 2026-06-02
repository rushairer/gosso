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
)

// RequestIDMiddleware injects a unique request ID into every request.
// If the incoming request already has an X-Request-ID header, it is preserved;
// otherwise a new UUID is generated.
func RequestIDMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		requestID := ctx.GetHeader(HeaderRequestID)
		if requestID == "" {
			requestID = uuid.New().String()
		}

		ctx.Set(ContextKeyRequestID, requestID)
		ctx.Header(HeaderRequestID, requestID)

		ctx.Next()
	}
}
