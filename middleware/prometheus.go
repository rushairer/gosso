package middleware

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/rushairer/gosso/internal/observability"
)

// PrometheusMiddleware returns a Gin middleware that records HTTP request count
// and duration using the provided Metrics. Route patterns (e.g. "/api/auth/login")
// are used as the path label, not the actual request path, to avoid cardinality explosion.
func PrometheusMiddleware(metrics *observability.Metrics) gin.HandlerFunc {
	return func(c *gin.Context) {
		if metrics == nil {
			c.Next()
			return
		}

		start := time.Now()
		c.Next()
		duration := time.Since(start).Seconds()

		// Use the matched route pattern if available, otherwise fallback to a generic label.
		path := c.FullPath()
		if path == "" {
			path = "unknown"
		}

		method := c.Request.Method
		status := strconv.Itoa(c.Writer.Status())

		metrics.HTTPRequestsTotal.With(prometheus.Labels{
			"method": method,
			"path":   path,
			"status": status,
		}).Inc()

		metrics.HTTPRequestDuration.With(prometheus.Labels{
			"method": method,
			"path":   path,
		}).Observe(duration)
	}
}
