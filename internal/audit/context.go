package audit

import "context"

type contextKey string

const (
	keyIP        contextKey = "audit_ip"
	keyUserAgent contextKey = "audit_user_agent"
	keyRequestID contextKey = "audit_request_id"
)

// SetMetadata stores client IP, user agent, and request ID in context for audit logging.
func SetMetadata(ctx context.Context, ip, userAgent, requestID string) context.Context {
	ctx = context.WithValue(ctx, keyIP, ip)
	ctx = context.WithValue(ctx, keyUserAgent, userAgent)
	ctx = context.WithValue(ctx, keyRequestID, requestID)
	return ctx
}

// IPFromContext extracts client IP from context.
func IPFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(keyIP).(string); ok {
		return v
	}
	return ""
}

// UserAgentFromContext extracts user agent from context.
func UserAgentFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(keyUserAgent).(string); ok {
		return v
	}
	return ""
}

// RequestIDFromContext extracts request ID from context.
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(keyRequestID).(string); ok {
		return v
	}
	return ""
}
