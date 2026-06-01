package audit

import "context"

type contextKey string

const (
	keyIP        contextKey = "audit_ip"
	keyUserAgent contextKey = "audit_user_agent"
)

// SetMetadata stores client IP and user agent in context for audit logging.
// Use ginCtx.Request = ginCtx.Request.WithContext(audit.SetMetadata(ginCtx.Request.Context(), ip, ua))
func SetMetadata(ctx context.Context, ip, userAgent string) context.Context {
	ctx = context.WithValue(ctx, keyIP, ip)
	ctx = context.WithValue(ctx, keyUserAgent, userAgent)
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
