package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/rushairer/gouno"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/utility"
)

// slidingWindowScript Redis Lua sliding window rate limiter script
// KEYS[1] = rate limit key
// ARGV[1] = window in seconds
// ARGV[2] = max requests limit
// Uses Redis server TIME instead of client-provided timestamp for consistency across instances.
var slidingWindowScript = redis.NewScript(`
local key = KEYS[1]
local window_sec = tonumber(ARGV[1])
local window_ms = window_sec * 1000
local limit = tonumber(ARGV[2])
local timeArr = redis.call('TIME')
local now_sec = tonumber(timeArr[1])
local now_ms = now_sec * 1000 + math.floor(tonumber(timeArr[2]) / 1000)

redis.call('ZREMRANGEBYSCORE', key, 0, now_ms - window_ms)
local count = redis.call('ZCARD', key)

local allowed = 0
local remaining = 0
if count < limit then
    redis.call('ZADD', key, now_ms, now_ms .. ':' .. timeArr[2])
    allowed = 1
    remaining = limit - count - 1
else
    allowed = 0
    remaining = 0
end

redis.call('EXPIRE', key, window_sec)

local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
local reset_at = now_sec + window_sec
local retry_after = window_sec
if #oldest > 0 then
    local oldest_score = tonumber(oldest[2])
    reset_at = math.ceil((oldest_score + window_ms) / 1000)
    local diff = oldest_score + window_ms - now_ms
    if diff > 0 then
        retry_after = math.ceil(diff / 1000)
    else
        retry_after = 0
    end
    if retry_after > window_sec then
        retry_after = window_sec
    end
end

return {allowed, remaining, reset_at, retry_after}
`)

// RedisRateLimitMiddleware Redis-based distributed sliding window rate limiter middleware.
// endpoint: identifies the rate-limited resource (e.g., "login", "token") to avoid key collisions.
// keyFunc: extracts rate limit key from request (e.g., IP, accountID).
// limit: max requests within the window.
// window: time window duration.
// failOpen: if true, allows requests when Redis is unavailable (fail-open);
// if false, rejects requests with 503 when Redis is unavailable (fail-closed).
func RedisRateLimitMiddleware(rds *cache.RedisClient, endpoint string, keyFunc func(*gin.Context) string, limit int, window time.Duration, failOpen bool, logger *zap.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		key := fmt.Sprintf("rate_limit|%s|%s", endpoint, keyFunc(ctx))

		result, err := rds.RunScript(ctx, slidingWindowScript,
			[]string{key},
			int(window.Seconds()),
			limit,
		).Int64Slice()

		if err != nil {
			if logger != nil {
				logger.Error("Rate limiter Redis error", zap.String("key", key), zap.Error(err))
			}
			if failOpen {
				ctx.Next()
			} else {
				ctx.JSON(http.StatusServiceUnavailable, gouno.NewErrorResponse(http.StatusServiceUnavailable, "rate limit service unavailable"))
				ctx.Abort()
			}
			return
		}

		if len(result) < 4 {
			if failOpen {
				ctx.Next()
			} else {
				ctx.JSON(http.StatusServiceUnavailable, gouno.NewErrorResponse(http.StatusServiceUnavailable, "rate limit service unavailable"))
				ctx.Abort()
			}
			return
		}

		allowed := result[0] == 1
		remaining := result[1]
		resetAt := result[2]
		retryAfter := result[3]

		ctx.Header("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
		ctx.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		ctx.Header("X-RateLimit-Reset", fmt.Sprintf("%d", resetAt))

		if !allowed {
			ctx.Header("Retry-After", fmt.Sprintf("%d", retryAfter))
			ctx.JSON(http.StatusTooManyRequests, gouno.NewErrorResponse(http.StatusTooManyRequests, "rate limit exceeded"))
			ctx.Abort()
			return
		}

		ctx.Next()
	}
}

// IPKeyFunc extracts rate limit key based on client IP.
// Normalizes IPv4-mapped IPv6 addresses to prevent rate limit bypass.
func IPKeyFunc(ctx *gin.Context) string {
	return utility.NormalizeIP(ctx.ClientIP())
}
