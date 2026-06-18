package router

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rushairer/gosso/internal/testutil"
)

func TestHealthRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("health endpoint returns status ok", func(t *testing.T) {
		server := gin.New()
		registerHealthRoutes(server, nil, nil)

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

		registerHealthRoutes(server, db, redisClient)

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

		registerHealthRoutes(server, db, redisClient)

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
