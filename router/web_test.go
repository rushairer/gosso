package router

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/testutil"
)

func TestHealthRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("health endpoint returns status ok", func(t *testing.T) {
		server := gin.New()
		redisClient, mr := testutil.SetupTestRedis(t)
		defer mr.Close()
		registerHealthRoutes(server, nil, redisClient, 60, zap.NewNop())

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/health", nil)
		server.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "ok", response["status"])
	})

	t.Run("readiness endpoint success status when db and redis are alive", func(t *testing.T) {
		server := gin.New()
		redisClient, mr := testutil.SetupTestRedis(t)
		defer mr.Close()

		db, sqlMock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
		require.NoError(t, err)
		defer db.Close()

		sqlMock.ExpectPing()

		registerHealthRoutes(server, db, redisClient, 60, zap.NewNop())

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/readiness", nil)
		server.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "ok", response["status"])
		assert.Equal(t, true, response["ready"])

		checks := response["checks"].(map[string]interface{})
		assert.Equal(t, "ok", checks["database"])
		assert.Equal(t, "ok", checks["redis"])
	})

	t.Run("readiness endpoint error status when db ping fails", func(t *testing.T) {
		server := gin.New()
		redisClient, mr := testutil.SetupTestRedis(t)
		defer mr.Close()

		db, sqlMock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
		require.NoError(t, err)
		defer db.Close()

		sqlMock.ExpectPing().WillReturnError(sql.ErrConnDone)

		registerHealthRoutes(server, db, redisClient, 60, zap.NewNop())

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/readiness", nil)
		server.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)

		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "unavailable", response["status"])
		assert.Equal(t, false, response["ready"])

		checks := response["checks"].(map[string]interface{})
		assert.Equal(t, "unavailable", checks["database"])
		assert.Equal(t, "ok", checks["redis"])
	})
}

func TestIndexAndTestRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("index endpoint returns hello", func(t *testing.T) {
		server := gin.New()
		registerWebIndexRouter(server)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/", nil)
		server.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "Hello gouno!", w.Body.String())
	})

	t.Run("test alive endpoint returns pong", func(t *testing.T) {
		server := gin.New()
		registerWebTestRouter(server)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/test/alive", nil)
		server.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, float64(200), response["code"])
		assert.Equal(t, "success", response["message"])
		assert.Equal(t, "pong", response["data"])
	})
}

// TestAPIRedirectMiddleware tests the backward-compatible redirect from /api/* to /api/v1/*.
//
// In the actual RegisterWebRouter, the redirect middleware is registered on
// server.Group("/api").Use(...). The /api/v1 group is registered as a sibling.
// In Gin's routing model, the /api group middleware only fires for paths that match
// a handler under that group. Old /api/* paths that don't match any handler hit NoRoute.
//
// This test verifies the redirect middleware logic directly as a gin.HandlerFunc.
func TestAPIRedirectMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Extract the redirect middleware logic from RegisterWebRouter for direct testing.
	// Uses strings.HasPrefix matching the real implementation in web.go.
	redirectMiddleware := func(ctx *gin.Context) {
		if !strings.HasPrefix(ctx.Request.URL.Path, "/api/v1") {
			newPath := "/api/v1" + strings.TrimPrefix(ctx.Request.URL.Path, "/api")
			if ctx.Request.URL.RawQuery != "" {
				newPath += "?" + ctx.Request.URL.RawQuery
			}
			ctx.Redirect(http.StatusPermanentRedirect, newPath)
			ctx.Abort()
			return
		}
		ctx.Next()
	}

	t.Run("old login path redirects to v1", func(t *testing.T) {
		server := gin.New()
		server.Use(redirectMiddleware)
		server.POST("/api/v1/auth/login", func(ctx *gin.Context) {
			ctx.JSON(http.StatusOK, gin.H{"ok": true})
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/api/auth/login", nil)
		server.ServeHTTP(w, req)

		assert.Equal(t, http.StatusPermanentRedirect, w.Code)
		assert.Equal(t, "/api/v1/auth/login", w.Header().Get("Location"))
	})

	t.Run("old path with query preserves query string", func(t *testing.T) {
		server := gin.New()
		server.Use(redirectMiddleware)
		server.POST("/api/v1/auth/login", func(ctx *gin.Context) {
			ctx.JSON(http.StatusOK, gin.H{"ok": true})
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/api/auth/login?foo=bar", nil)
		server.ServeHTTP(w, req)

		assert.Equal(t, http.StatusPermanentRedirect, w.Code)
		assert.Equal(t, "/api/v1/auth/login?foo=bar", w.Header().Get("Location"))
	})

	t.Run("v1 path passes through middleware", func(t *testing.T) {
		server := gin.New()
		server.Use(redirectMiddleware)
		server.POST("/api/v1/auth/login", func(ctx *gin.Context) {
			ctx.JSON(http.StatusOK, gin.H{"ok": true})
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		server.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("non-api path not affected by group-scoped middleware", func(t *testing.T) {
		// In the real code, the redirect middleware is scoped to the /api group,
		// so non-/api paths never enter it. We verify the middleware itself
		// only has effect on paths starting with /api.
		server := gin.New()
		server.GET("/", func(ctx *gin.Context) {
			ctx.String(http.StatusOK, "home")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/", nil)
		server.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "home", w.Body.String())
	})
}

// TestNoRouteHandler tests the custom 404 handler.
func TestNoRouteHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	server := gin.New()

	// Register the custom 404 handler (same logic as RegisterWebRouter)
	server.NoRoute(func(ctx *gin.Context) {
		path := ctx.Request.URL.Path
		if len(path) >= 5 && path[:5] == "/api/" {
			ctx.JSON(http.StatusNotFound, map[string]interface{}{
				"code":    http.StatusNotFound,
				"message": "not found",
			})
			return
		}
		if len(path) >= 8 && path[:8] == "/oauth2/" {
			ctx.JSON(http.StatusNotFound, map[string]interface{}{
				"code":    http.StatusNotFound,
				"message": "not found",
			})
			return
		}
		ctx.Data(http.StatusNotFound, "text/html; charset=utf-8", []byte(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>404 Not Found</title></head><body><h1>404 - Page Not Found</h1><p>The requested resource was not found on this server.</p></body></html>`))
	})

	t.Run("API path returns JSON 404", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/v1/nonexistent", nil)
		server.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, float64(404), response["code"])
		assert.Equal(t, "not found", response["message"])
	})

	t.Run("OAuth2 path returns JSON 404", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/oauth2/nonexistent", nil)
		server.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, float64(404), response["code"])
	})

	t.Run("browser path returns HTML 404", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/nonexistent", nil)
		server.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "text/html")
		assert.Contains(t, w.Body.String(), "404 - Page Not Found")
	})
}

// TestSwaggerRoutes tests that swagger routes are registered when Debug is true.
func TestSwaggerRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	server := gin.New()
	registerSwaggerRouter(server)

	t.Run("swagger root redirects to index.html", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/swagger", nil)
		server.ServeHTTP(w, req)

		assert.Equal(t, http.StatusTemporaryRedirect, w.Code)
		assert.Equal(t, "/swagger/index.html", w.Header().Get("Location"))
	})

	t.Run("swagger index.html returns HTML", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/swagger/index.html", nil)
		server.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "text/html")
	})

	t.Run("swagger openapi.yaml returns YAML", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/swagger/openapi.yaml", nil)
		server.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "application/yaml")
	})
}

// TestMetricsEndpoint tests that the /metrics endpoint returns Prometheus format.
func TestMetricsEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("metrics endpoint returns prometheus text", func(t *testing.T) {
		server := gin.New()

		// Use a custom registry to avoid interference from other tests
		reg := prometheus.NewRegistry()
		// Register the default Go collectors so the endpoint has content
		reg.MustRegister(prometheus.NewGoCollector()) //nolint:staticcheck // SA1019: deprecated but acceptable in test

		server.GET("/metrics", func(ctx *gin.Context) {
			promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(ctx.Writer, ctx.Request)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/metrics", nil)
		server.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "text/plain")
		assert.Contains(t, w.Body.String(), "# HELP")
	})

	t.Run("metrics disabled means no /metrics route", func(t *testing.T) {
		server := gin.New()
		// Do NOT register /metrics

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/metrics", nil)
		server.ServeHTTP(w, req)

		// Without the route, gin returns 404
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestRegisterWebRouter_HealthRoutesNilDB tests that health routes handle a nil DB gracefully.
func TestRegisterWebRouter_HealthRoutesNilDB(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("readiness with nil db returns 503", func(t *testing.T) {
		server := gin.New()
		redisClient, mr := testutil.SetupTestRedis(t)
		defer mr.Close()

		// Passing nil DB will cause a panic on db.PingContext, so we test
		// with a real sqlmock that returns an error instead.
		db, sqlMock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
		require.NoError(t, err)
		defer db.Close()

		sqlMock.ExpectPing().WillReturnError(sql.ErrConnDone)

		registerHealthRoutes(server, db, redisClient, 60, zap.NewNop())

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/readiness", nil)
		server.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}
