package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// EventsTotal tracks total events processed by source
	EventsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "xdr_events_total",
			Help: "Total number of XDR events processed",
		},
		[]string{"source", "event_type", "severity"},
	)

	// EventsProcessingDuration tracks event processing time
	EventsProcessingDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "xdr_events_processing_duration_seconds",
			Help:    "Time spent processing events",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"source"},
	)

	// IncidentsTotal tracks total incidents created
	IncidentsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "xdr_incidents_total",
			Help: "Total number of incidents created",
		},
		[]string{"incident_type", "severity"},
	)

	// AssetTrustScore tracks asset trust scores
	AssetTrustScore = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "xdr_asset_trust_score",
			Help: "Current trust score for assets",
		},
		[]string{"asset_id", "asset_type"},
	)

	// CTIMatchesTotal tracks IoC matches
	CTIMatchesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "xdr_cti_matches_total",
			Help: "Total number of CTI IoC matches",
		},
		[]string{"ioc_type", "source"},
	)

	// PlaybookExecutionsTotal tracks playbook executions
	PlaybookExecutionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "xdr_playbook_executions_total",
			Help: "Total number of playbook executions",
		},
		[]string{"playbook_id", "status"},
	)

	// HTTPRequestsTotal tracks HTTP requests
	HTTPRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "xdr_http_requests_total",
			Help: "Total HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	// HTTPRequestDuration tracks HTTP request duration
	HTTPRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "xdr_http_request_duration_seconds",
			Help:    "HTTP request duration",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)
)

func init() {
	prometheus.MustRegister(
		EventsTotal,
		EventsProcessingDuration,
		IncidentsTotal,
		AssetTrustScore,
		CTIMatchesTotal,
		PlaybookExecutionsTotal,
		HTTPRequestsTotal,
		HTTPRequestDuration,
	)
}

// Handler returns the Prometheus metrics handler
func Handler() http.Handler {
	return promhttp.Handler()
}

// Middleware returns an HTTP middleware that tracks request metrics
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		duration := time.Since(start).Seconds()

		HTTPRequestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration)
	})
}
