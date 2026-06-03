package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/rushairer/gosso/internal/cache"
)

// slidingWindowScript Redis Lua sliding window rate limiter script
// KEYS[1] = rate limit key
// ARGV[1] = window in seconds
// ARGV[2] = max requests limit
// Uses Redis server TIME instead of client-provided timestamp for consistency across instances.
var slidingWindowScript = redis.NewScript(`
local key = KEYS[1]
local window = tonumber(ARGV[1]) * 1000
local limit = tonumber(ARGV[2])
local timeArr = redis.call('TIME')
local now = tonumber(timeArr[1]) * 1000 + math.floor(tonumber(timeArr[2]) / 1000)

redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local count = redis.call('ZCARD', key)
if count < limit then
    redis.call('ZADD', key, now, now .. ':' .. timeArr[2])
    if count == 0 then
        redis.call('EXPIRE', key, ARGV[1])
    end
    return {1, limit - count - 1}
end
redis.call('EXPIRE', key, ARGV[1])
return {0, 0}
`)

// RedisRateLimitMiddleware Redis-based distributed sliding window rate limiter middleware.
// keyFunc: extracts rate limit key from request (e.g., IP, accountID).
// limit: max requests within the window.
// window: time window duration.
// failOpen: if true, allows requests when Redis is unavailable (fail-open);
// if false, rejects requests with 503 when Redis is unavailable (fail-closed).
func RedisRateLimitMiddleware(rds *cache.RedisClient, keyFunc func(*gin.Context) string, limit int, window time.Duration, failOpen bool) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		key := fmt.Sprintf("rate_limit:%s", keyFunc(ctx))

		result, err := slidingWindowScript.Run(ctx, rds.GetClient(),
			[]string{key},
			int(window.Seconds()),
			limit,
		).Int64Slice()

		if err != nil {
			if failOpen {
				ctx.Next()
			} else {
				ctx.JSON(http.StatusServiceUnavailable, gin.H{
					"code":    503,
					"message": "rate limit service unavailable",
				})
				ctx.Abort()
			}
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

// IPKeyFunc extracts rate limit key based on client IP.
func IPKeyFunc(ctx *gin.Context) string {
	return ctx.ClientIP()
}
