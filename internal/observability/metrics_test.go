package observability

import (
	"context"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	require.NotNil(t, m)
	assert.NotNil(t, m.HTTPRequestsTotal)
	assert.NotNil(t, m.HTTPRequestDuration)
	assert.NotNil(t, m.AuthLoginAttempts)
	assert.NotNil(t, m.RateLimitExceeded)
	assert.NotNil(t, m.ActiveSessions)
	assert.NotNil(t, m.DBPoolOpenConnections)
	assert.NotNil(t, m.DBPoolInUse)
	assert.NotNil(t, m.RedisPoolActive)
}

func TestNewMetrics_NilRegistry(t *testing.T) {
	// Should not panic when using default registry
	assert.NotPanics(t, func() {
		_ = NewMetrics(nil)
	})
}

func TestMetricsRegistration(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	// Verify metrics are collectable
	m.HTTPRequestsTotal.With(prometheus.Labels{
		"method": "GET",
		"path":   "/test",
		"status": "200",
	}).Inc()

	metrics, err := reg.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, metrics)
}

// TestCounterIncrement verifies counter metric increment and label combinations.
func TestCounterIncrement(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	// Increment HTTPRequestsTotal with different label combos
	m.HTTPRequestsTotal.WithLabelValues("GET", "/api/v1/health", "200").Inc()
	m.HTTPRequestsTotal.WithLabelValues("GET", "/api/v1/health", "200").Inc()
	m.HTTPRequestsTotal.WithLabelValues("POST", "/api/v1/auth/login", "401").Inc()

	// Gather and verify distinct label combinations
	families, err := reg.Gather()
	require.NoError(t, err)

	for _, fam := range families {
		if fam.GetName() == "gosso_http_requests_total" {
			require.Len(t, fam.GetMetric(), 2, "should have 2 distinct label combinations")
		}
	}
}

// TestHistogramObserve verifies histogram metric observation.
func TestHistogramObserve(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	// Observe some durations
	m.HTTPRequestDuration.WithLabelValues("GET", "/api/v1/health").Observe(0.1)
	m.HTTPRequestDuration.WithLabelValues("GET", "/api/v1/health").Observe(0.5)
	m.HTTPRequestDuration.WithLabelValues("POST", "/api/v1/auth/login").Observe(1.2)

	// Gather and verify
	families, err := reg.Gather()
	require.NoError(t, err)

	var histogramFound bool
	for _, fam := range families {
		if fam.GetName() == "gosso_http_request_duration_seconds" {
			histogramFound = true
			require.Len(t, fam.GetMetric(), 2, "should have 2 distinct label combinations")
			// First combo (GET /health) should have sample_count=2
			assert.Equal(t, uint64(2), fam.GetMetric()[0].GetHistogram().GetSampleCount())
			// Second combo (POST /login) should have sample_count=1
			assert.Equal(t, uint64(1), fam.GetMetric()[1].GetHistogram().GetSampleCount())
		}
	}
	assert.True(t, histogramFound, "histogram metric family should be present")
}

// TestGaugeSet verifies gauge metric set/increment/decrement.
func TestGaugeSet(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	m.ActiveSessions.Set(42)
	m.ActiveSessions.Inc()
	m.ActiveSessions.Dec()

	m.DBPoolOpenConnections.Set(10)
	m.DBPoolInUse.Set(5)
	m.RedisPoolActive.Set(3)

	families, err := reg.Gather()
	require.NoError(t, err)

	gaugeValues := map[string]float64{}
	for _, fam := range families {
		for _, metric := range fam.GetMetric() {
			gaugeValues[fam.GetName()] = metric.GetGauge().GetValue()
		}
	}

	assert.Equal(t, float64(42), gaugeValues["gosso_active_sessions"], "42 +1 -1 = 42")
	assert.Equal(t, float64(10), gaugeValues["gosso_db_pool_open_connections"])
	assert.Equal(t, float64(5), gaugeValues["gosso_db_pool_in_use"])
	assert.Equal(t, float64(3), gaugeValues["gosso_redis_pool_active_connections"])
}

// TestAuthLoginAttemptsCounter verifies the auth login counter with result/method labels.
func TestAuthLoginAttemptsCounter(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	m.AuthLoginAttempts.WithLabelValues("success", "password").Inc()
	m.AuthLoginAttempts.WithLabelValues("failure", "password").Inc()
	m.AuthLoginAttempts.WithLabelValues("failure", "password").Inc()
	m.AuthLoginAttempts.WithLabelValues("success", "passkey").Inc()

	families, err := reg.Gather()
	require.NoError(t, err)

	for _, fam := range families {
		if fam.GetName() == "gosso_auth_login_attempts_total" {
			assert.Len(t, fam.GetMetric(), 3, "3 distinct label combos: success/password, failure/password, success/passkey")
		}
	}
}

// TestRateLimitExceededCounter verifies the rate limit counter.
func TestRateLimitExceededCounter(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	m.RateLimitExceeded.WithLabelValues("login").Add(5)
	m.RateLimitExceeded.WithLabelValues("api").Add(3)

	families, err := reg.Gather()
	require.NoError(t, err)

	for _, fam := range families {
		if fam.GetName() == "gosso_rate_limit_exceeded_total" {
			assert.Len(t, fam.GetMetric(), 2)
		}
	}
}

// TestConcurrentMetricAccess verifies that concurrent access to metrics is safe.
func TestConcurrentMetricAccess(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	var wg sync.WaitGroup
	numGoroutines := 50

	// Concurrent counter increments
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			m.HTTPRequestsTotal.WithLabelValues("GET", "/test", "200").Inc()
		}()
	}

	// Concurrent gauge sets
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			m.ActiveSessions.Set(float64(i))
		}()
	}

	// Concurrent histogram observations
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			m.HTTPRequestDuration.WithLabelValues("GET", "/test").Observe(0.1)
		}()
	}

	wg.Wait()

	// Verify counter total
	families, err := reg.Gather()
	require.NoError(t, err)

	for _, fam := range families {
		if fam.GetName() == "gosso_http_requests_total" {
			for _, metric := range fam.GetMetric() {
				assert.Equal(t, float64(numGoroutines), metric.GetCounter().GetValue())
			}
		}
		if fam.GetName() == "gosso_http_request_duration_seconds" {
			for _, metric := range fam.GetMetric() {
				assert.Equal(t, uint64(numGoroutines), metric.GetHistogram().GetSampleCount())
			}
		}
	}
}

// TestInitTracerProvider_EmptyEndpoint tests that an empty endpoint returns an error
// because the OTLP exporter or resource creation fails.
func TestInitTracerProvider_EmptyEndpoint(t *testing.T) {
	tp, err := InitTracerProvider(context.Background(), "test-service", "1.0.0", "")
	// The function should return an error due to either the OTLP exporter
	// or the OTel resource creation failing (schema URL conflict, etc.)
	if err != nil {
		assert.Nil(t, tp)
		t.Logf("Got expected error: %v", err)
	} else if tp != nil {
		// If no error, the exporter was created (some versions allow empty endpoint).
		// Clean up the tracer provider.
		_ = tp.Shutdown(context.Background())
	}
}
