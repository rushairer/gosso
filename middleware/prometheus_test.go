package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rushairer/gosso/internal/observability"
)

// setupPrometheusTestRouter creates a Gin engine with PrometheusMiddleware and
// a /test route. The Metrics are built on a custom registry so tests never
// pollute the global Prometheus default.
func setupPrometheusTestRouter(metrics *observability.Metrics) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(PrometheusMiddleware(metrics))
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	r.POST("/test", func(c *gin.Context) {
		c.String(http.StatusCreated, "created")
	})
	r.GET("/other", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	return r
}

// newTestMetrics builds Metrics on an isolated registry and returns the
// registry alongside the Metrics so tests can gather collected samples.
func newTestMetrics() (*observability.Metrics, *prometheus.Registry) {
	reg := prometheus.NewRegistry()
	m := observability.NewMetrics(reg)
	return m, reg
}

// getCounterValue gathers the counter family matching metricName from reg and
// returns the value of the first sample whose labels match the provided subset.
func getCounterValue(t *testing.T, reg *prometheus.Registry, metricName string, labels prometheus.Labels) float64 {
	t.Helper()
	families, err := reg.Gather()
	require.NoError(t, err)
	for _, fam := range families {
		if fam.GetName() == metricName {
			for _, m := range fam.GetMetric() {
				if matchLabels(m, labels) {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

// getHistogramCount gathers the histogram family matching metricName and returns
// the sample count of the first sample whose labels match the provided subset.
func getHistogramCount(t *testing.T, reg *prometheus.Registry, metricName string, labels prometheus.Labels) uint64 {
	t.Helper()
	families, err := reg.Gather()
	require.NoError(t, err)
	for _, fam := range families {
		if fam.GetName() == metricName {
			for _, m := range fam.GetMetric() {
				if matchLabels(m, labels) {
					return m.GetHistogram().GetSampleCount()
				}
			}
		}
	}
	return 0
}

// matchLabels returns true when every entry in want exists as a label pair on m.
func matchLabels(m *dto.Metric, want prometheus.Labels) bool {
	pairs := m.GetLabel()
	for k, v := range want {
		found := false
		for _, p := range pairs {
			if p.GetName() == k && p.GetValue() == v {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestPrometheusMiddleware_NormalRequest(t *testing.T) {
	metrics, reg := newTestMetrics()
	r := setupPrometheusTestRouter(metrics)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	wantLabels := prometheus.Labels{"method": "GET", "path": "/test", "status": "200"}
	assert.Equal(t, float64(1), getCounterValue(t, reg, "gosso_http_requests_total", wantLabels),
		"http_requests_total should be 1 for GET /test 200")

	wantHistLabels := prometheus.Labels{"method": "GET", "path": "/test"}
	assert.Equal(t, uint64(1), getHistogramCount(t, reg, "gosso_http_request_duration_seconds", wantHistLabels),
		"http_request_duration_seconds sample count should be 1 for GET /test")
}

func TestPrometheusMiddleware_NilMetrics(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(PrometheusMiddleware(nil))
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	// Must not panic.
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestPrometheusMiddleware_UnknownPath(t *testing.T) {
	metrics, reg := newTestMetrics()

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(PrometheusMiddleware(metrics))
	// Register a handler that does NOT use a named route pattern in Gin's tree,
	// so c.FullPath() returns "".
	r.NoRoute(func(c *gin.Context) {
		c.String(http.StatusNotFound, "not found")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/does-not-exist", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	wantLabels := prometheus.Labels{"method": "GET", "path": "unknown", "status": "404"}
	assert.Equal(t, float64(1), getCounterValue(t, reg, "gosso_http_requests_total", wantLabels),
		"unmatched route should use path=unknown")
}

func TestPrometheusMiddleware_MultipleRequests(t *testing.T) {
	metrics, reg := newTestMetrics()
	r := setupPrometheusTestRouter(metrics)

	// Send 3 requests: 2x GET /test, 1x POST /test.
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}
	{
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusCreated, w.Code)
	}

	getLabels := prometheus.Labels{"method": "GET", "path": "/test", "status": "200"}
	assert.Equal(t, float64(2), getCounterValue(t, reg, "gosso_http_requests_total", getLabels),
		"GET /test 200 counter should be 2")

	postLabels := prometheus.Labels{"method": "POST", "path": "/test", "status": "201"}
	assert.Equal(t, float64(1), getCounterValue(t, reg, "gosso_http_requests_total", postLabels),
		"POST /test 201 counter should be 1")

	getHistLabels := prometheus.Labels{"method": "GET", "path": "/test"}
	assert.Equal(t, uint64(2), getHistogramCount(t, reg, "gosso_http_request_duration_seconds", getHistLabels),
		"GET /test histogram sample count should be 2")

	postHistLabels := prometheus.Labels{"method": "POST", "path": "/test"}
	assert.Equal(t, uint64(1), getHistogramCount(t, reg, "gosso_http_request_duration_seconds", postHistLabels),
		"POST /test histogram sample count should be 1")
}

func TestPrometheusMiddleware_DifferentRoutes(t *testing.T) {
	metrics, reg := newTestMetrics()
	r := setupPrometheusTestRouter(metrics)

	// GET /test
	{
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}
	// GET /other
	{
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/other", nil)
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}

	testLabels := prometheus.Labels{"method": "GET", "path": "/test", "status": "200"}
	assert.Equal(t, float64(1), getCounterValue(t, reg, "gosso_http_requests_total", testLabels),
		"GET /test counter should be 1")

	otherLabels := prometheus.Labels{"method": "GET", "path": "/other", "status": "200"}
	assert.Equal(t, float64(1), getCounterValue(t, reg, "gosso_http_requests_total", otherLabels),
		"GET /other counter should be 1")
}
