package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/testutil"
)

func TestIPKeyFunc(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request, _ = http.NewRequest("GET", "/", nil)
	ctx.Request.RemoteAddr = "192.168.1.1:12345"

	key := IPKeyFunc(ctx)
	assert.NotEmpty(t, key)
}

func TestIPKeyFunc_Localhost(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request, _ = http.NewRequest("GET", "/", nil)
	ctx.Request.RemoteAddr = "127.0.0.1:8080"

	key := IPKeyFunc(ctx)
	assert.Equal(t, "127.0.0.1", key)
}

func TestIPKeyFunc_XForwardedFor(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request, _ = http.NewRequest("GET", "/", nil)
	ctx.Request.RemoteAddr = "10.0.0.1:12345"
	ctx.Request.Header.Set("X-Forwarded-For", "203.0.113.50")

	key := IPKeyFunc(ctx)
	assert.Equal(t, "203.0.113.50", key)
}

// ──────────────────────────────────────────────
// RedisRateLimitMiddleware — unit tests (miniredis)
// ──────────────────────────────────────────────

func TestRedisRateLimit_Unit_AllowWithinLimit(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/test",
		RedisRateLimitMiddleware(redisClient, "unit", IPKeyFunc, 5, time.Minute, true, zap.NewNop()),
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) },
	)

	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		engine.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "request %d should succeed", i+1)
	}
}

func TestRedisRateLimit_Unit_BlockOverLimit(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/test",
		RedisRateLimitMiddleware(redisClient, "unit", IPKeyFunc, 3, time.Minute, true, zap.NewNop()),
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) },
	)

	// Exhaust the limit
	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "10.0.0.2:12345"
		engine.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, "request %d should succeed", i+1)
	}

	// 4th request should be blocked
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.2:12345"
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
	assert.Equal(t, "3", w.Header().Get("X-RateLimit-Limit"))
	assert.Equal(t, "0", w.Header().Get("X-RateLimit-Remaining"))
}

func TestRedisRateLimit_Unit_ResponseHeaders(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/test",
		RedisRateLimitMiddleware(redisClient, "unit", IPKeyFunc, 10, time.Minute, true, zap.NewNop()),
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) },
	)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.5:12345"
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "10", w.Header().Get("X-RateLimit-Limit"))
	assert.NotEmpty(t, w.Header().Get("X-RateLimit-Remaining"))
	assert.NotEmpty(t, w.Header().Get("X-RateLimit-Reset"))
}

func TestRedisRateLimit_Unit_DifferentEndpointsIndependent(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/a",
		RedisRateLimitMiddleware(redisClient, "endpoint-a", IPKeyFunc, 2, time.Minute, true, zap.NewNop()),
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) },
	)
	engine.GET("/b",
		RedisRateLimitMiddleware(redisClient, "endpoint-b", IPKeyFunc, 2, time.Minute, true, zap.NewNop()),
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) },
	)

	// Exhaust endpoint-a for a specific IP
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/a", nil)
		req.RemoteAddr = "10.0.0.3:12345"
		engine.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, "request %d should succeed", i+1)
	}

	// endpoint-a should now be blocked for that IP
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/a", nil)
	req.RemoteAddr = "10.0.0.3:12345"
	engine.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	// endpoint-b should still work for same IP
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/b", nil)
	req.RemoteAddr = "10.0.0.3:12345"
	engine.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRedisRateLimit_Unit_FailOpen_RedisDown(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/test",
		RedisRateLimitMiddleware(redisClient, "down-open", IPKeyFunc, 5, time.Minute, true, zap.NewNop()),
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) },
	)

	// Shut down Redis to simulate an outage
	mr.Close()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.4:12345"
	engine.ServeHTTP(w, req)

	// fail-open: request should be allowed through
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRedisRateLimit_Unit_FailClosed_RedisDown(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/test",
		RedisRateLimitMiddleware(redisClient, "down-closed", IPKeyFunc, 5, time.Minute, false, zap.NewNop()),
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) },
	)

	// Shut down Redis to simulate an outage
	mr.Close()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.5:12345"
	engine.ServeHTTP(w, req)

	// fail-closed: request should be rejected with 503
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestRedisRateLimit_Unit_NilLogger(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/test",
		// nil logger should not panic on successful request
		RedisRateLimitMiddleware(redisClient, "nil-logger", IPKeyFunc, 5, time.Minute, true, nil),
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) },
	)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.6:12345"
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
