package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gosso/internal/cache"
	"github.com/redis/go-redis/v9"
)

// slidingWindowScript Redis Lua 滑动窗口限流脚本
var slidingWindowScript = redis.NewScript(`
local key = KEYS[1]
local window = tonumber(ARGV[1]) * 1000
local limit = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local count = redis.call('ZCARD', key)
if count < limit then
    redis.call('ZADD', key, now, now .. ':' .. math.random(1000000))
    redis.call('EXPIRE', key, ARGV[1])
    return {1, limit - count - 1}
end
return {0, 0}
`)

// RedisRateLimitMiddleware 基于 Redis 的分布式滑动窗口限流中间件
// keyFunc: 从请求中提取限流 key（如 IP、accountID）
// limit: 窗口内最大请求数
// window: 时间窗口
func RedisRateLimitMiddleware(rds *cache.RedisClient, keyFunc func(*gin.Context) string, limit int, window time.Duration) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		key := fmt.Sprintf("rate_limit:%s", keyFunc(ctx))
		now := time.Now().UnixMilli()

		result, err := slidingWindowScript.Run(ctx, rds.GetClient(),
			[]string{key},
			int(window.Seconds()),
			limit,
			now,
		).Int64Slice()

		if err != nil {
			// Redis 故障时放行（fail-open）
			ctx.Next()
			return
		}

		allowed := result[0] == 1
		remaining := result[1]

		resetAt := time.Now().Add(window).Unix()
		ctx.Header("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
		ctx.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		ctx.Header("X-RateLimit-Reset", fmt.Sprintf("%d", resetAt))

		if !allowed {
			retryAfter := int(window.Seconds())
			ctx.Header("Retry-After", fmt.Sprintf("%d", retryAfter))
			ctx.JSON(http.StatusTooManyRequests, gin.H{
				"code":    429,
				"message": "rate limit exceeded",
			})
			ctx.Abort()
			return
		}

		ctx.Next()
	}
}

// IPKeyFunc 基于客户端 IP 的 key 提取函数
func IPKeyFunc(ctx *gin.Context) string {
	return ctx.ClientIP()
}
