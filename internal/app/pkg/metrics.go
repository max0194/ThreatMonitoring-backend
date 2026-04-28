package pkg

import (
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	httpRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Количество HTTP запросов",
		},
		[]string{"method", "endpoint", "status"},
	)

	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Длительность HTTP запросов",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint"},
	)

	httpErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_errors_total",
			Help: "Количество HTTP‑ошибок (4xx и 5xx)",
		},
		[]string{"status", "endpoint"},
	)

	loginSuccess = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "login_success_total",
			Help: "Количество успешных авторизаций",
		})
)

func init() {
	prometheus.MustRegister(
		httpRequests,
		httpRequestDuration,
		httpErrors,
		loginSuccess,
	)
}

func PrometheusMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		duration := time.Since(start).Seconds()
		status := fmt.Sprintf("%d", c.Writer.Status())

		httpRequests.WithLabelValues(
			c.Request.Method,
			c.FullPath(),
			status,
		).Inc()

		httpRequestDuration.WithLabelValues(
			c.Request.Method,
			c.FullPath(),
		).Observe(duration)

		if strings.HasPrefix(status, "4") || strings.HasPrefix(status, "5") {
			httpErrors.WithLabelValues(status, c.FullPath()).Inc()
		}
	}
}

func IncrementLoginSuccess() {
	loginSuccess.Inc()
}

func MetricsHandler() gin.HandlerFunc {
	handler := promhttp.Handler()
	return func(c *gin.Context) {
		handler.ServeHTTP(c.Writer, c.Request)
	}
}
