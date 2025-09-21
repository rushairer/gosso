package context

import (
	"context"
	"time"
)

// AuthInfo 认证信息
type AuthInfo struct {
	UserID    int64
	SessionID string
	Token     string
	ExpiresAt time.Time
	Role      string
}

type authInfoKey struct{}

func WithAuthInfo(ctx context.Context, auth *AuthInfo) context.Context {
	return context.WithValue(ctx, authInfoKey{}, auth)
}

func GetAuthInfo(ctx context.Context) (*AuthInfo, bool) {
	auth, ok := ctx.Value(authInfoKey{}).(*AuthInfo)
	return auth, ok
}

func MustGetAuthInfo(ctx context.Context) *AuthInfo {
	auth, ok := GetAuthInfo(ctx)
	if !ok {
		panic("no auth info in context")
	}
	return auth
}
