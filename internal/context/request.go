package context

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
)

// RequestInfo 请求信息
type RequestInfo struct {
	RequestID string
	ClientIP  string
	UserAgent string
	StartTime time.Time
	TraceID   string
}

type requestInfoKey struct{}

func NewRequestInfo(c *gin.Context) *RequestInfo {
	return &RequestInfo{
		RequestID: c.GetHeader("X-Request-ID"),
		ClientIP:  c.ClientIP(),
		UserAgent: c.GetHeader("User-Agent"),
		StartTime: time.Now(),
		TraceID:   c.GetHeader("X-Trace-ID"),
	}
}

func WithRequestInfo(ctx context.Context, req *RequestInfo) context.Context {
	return context.WithValue(ctx, requestInfoKey{}, req)
}

func GetRequestInfo(ctx context.Context) (*RequestInfo, bool) {
	req, ok := ctx.Value(requestInfoKey{}).(*RequestInfo)
	return req, ok
}
