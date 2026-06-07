//go:build integration

package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rushairer/gosso/internal/testutil"
	"github.com/rushairer/gosso/middleware"
)

var env *testutil.TestEnv

func TestMain(m *testing.M) {
	ctx := context.Background()
	var err error
	env, err = testutil.SetupTestEnv(ctx)
	if err != nil {
		os.Exit(0)
	}
	defer env.Cleanup()
	os.Exit(m.Run())
}

func setupRateLimitTest(t *testing.T) *gin.Engine {
	t.Helper()
	ctx := context.Background()
	rdb := env.Redis.GetClient()
	if rdb != nil {
		_ = rdb.FlushDB(ctx).Err()
	}

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	return engine
}

func TestRedisRateLimit_AllowsWithinLimit(t *testing.T) {
	engine := setupRateLimitTest(t)

	engine.GET("/test",
		middleware.RedisRateLimitMiddleware(env.Redis, "test", middleware.IPKeyFunc, 5, time.Minute, true, nil),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"ok": true})
		},
	)

	// First 5 requests should succeed
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		engine.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "request %d should succeed", i+1)
		assert.Equal(t, "5", w.Header().Get("X-RateLimit-Limit"))
	}
}

func TestRedisRateLimit_BlocksOverLimit(t *testing.T) {
	engine := setupRateLimitTest(t)

	engine.GET("/test",
		middleware.RedisRateLimitMiddleware(env.Redis, "test", middleware.IPKeyFunc, 3, time.Minute, true, nil),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"ok": true})
		},
	)

	// Exhaust the limit
	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "10.0.0.2:12345"
		engine.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
	}

	// 4th request should be blocked
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.2:12345"
	engine.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
}

func TestRedisRateLimit_DifferentKeysIndependent(t *testing.T) {
	engine := setupRateLimitTest(t)

	engine.GET("/test",
		middleware.RedisRateLimitMiddleware(env.Redis, "test", middleware.IPKeyFunc, 2, time.Minute, true, nil),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"ok": true})
		},
	)

	// Exhaust limit for IP 1
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "10.0.0.3:12345"
		engine.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
	}

	// IP 1 should be blocked
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.3:12345"
	engine.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	// IP 2 should still work
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.4:12345"
	engine.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRedisRateLimit_ResponseHeaders(t *testing.T) {
	engine := setupRateLimitTest(t)

	engine.GET("/test",
		middleware.RedisRateLimitMiddleware(env.Redis, "test", middleware.IPKeyFunc, 10, time.Minute, true, nil),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"ok": true})
		},
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
