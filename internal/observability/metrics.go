// Package observability provides Prometheus metrics and OpenTelemetry tracing
// for the gosso application.
package observability

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus collectors for the application.
type Metrics struct {
	HTTPRequestsTotal     *prometheus.CounterVec
	HTTPRequestDuration   *prometheus.HistogramVec
	AuthLoginAttempts     *prometheus.CounterVec
	RateLimitExceeded     *prometheus.CounterVec
	ActiveSessions        prometheus.Gauge
	DBPoolOpenConnections prometheus.Gauge
	DBPoolInUse           prometheus.Gauge
	RedisPoolActive       prometheus.Gauge
}

// NewMetrics creates and registers all Prometheus metrics.
// Use a custom registry to avoid conflicts with the default global registry.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	factory := promauto.With(reg)

	return &Metrics{
		HTTPRequestsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gosso_http_requests_total",
				Help: "Total number of HTTP requests processed, partitioned by method, path, and status code.",
			},
			[]string{"method", "path", "status"},
		),
		HTTPRequestDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "gosso_http_request_duration_seconds",
				Help:    "HTTP request duration in seconds, partitioned by method and path.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "path"},
		),
		AuthLoginAttempts: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gosso_auth_login_attempts_total",
				Help: "Total login attempts, partitioned by result (success/failure) and method (password/passkey/social).",
			},
			[]string{"result", "method"},
		),
		RateLimitExceeded: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gosso_rate_limit_exceeded_total",
				Help: "Total number of requests rejected by rate limiting, partitioned by endpoint.",
			},
			[]string{"endpoint"},
		),
		ActiveSessions: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "gosso_active_sessions",
				Help: "Current number of active sessions.",
			},
		),
		DBPoolOpenConnections: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "gosso_db_pool_open_connections",
				Help: "Number of open connections in the database connection pool.",
			},
		),
		DBPoolInUse: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "gosso_db_pool_in_use",
				Help: "Number of in-use connections in the database connection pool.",
			},
		),
		RedisPoolActive: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "gosso_redis_pool_active_connections",
				Help: "Number of active connections in the Redis connection pool.",
			},
		),
	}
}
