package metrics

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricName identifies a specific metric.
type MetricName string

const (
	MetricProofsGenerated MetricName = "proofs_generated_total"
	MetricProofsFailed    MetricName = "proofs_failed_total"
	MetricProofDuration   MetricName = "proof_duration_seconds"

	MetricRequestsBusy         MetricName = "requests_rejected_busy_total"
	MetricRequestsUnauthorized MetricName = "requests_unauthorized_total"
	MetricRequestsTooLarge     MetricName = "requests_too_large_total"

	MetricProofsInFlight MetricName = "proofs_in_flight"
)

const (
	NamespaceProofService = "proof_service"
	SubsystemZK           = "zk"
)

// Metrics provides access to proof-service metrics.
type Metrics struct{}

var (
	counters = map[MetricName]prometheus.Counter{
		MetricProofsGenerated: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: NamespaceProofService,
			Subsystem: SubsystemZK,
			Name:      string(MetricProofsGenerated),
			Help:      "Total number of proofs successfully generated",
		}),
		MetricProofsFailed: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: NamespaceProofService,
			Subsystem: SubsystemZK,
			Name:      string(MetricProofsFailed),
			Help:      "Total number of proof generation failures",
		}),
		MetricRequestsBusy: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: NamespaceProofService,
			Subsystem: SubsystemZK,
			Name:      string(MetricRequestsBusy),
			Help:      "Total number of requests rejected because all proving slots were busy",
		}),
		MetricRequestsUnauthorized: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: NamespaceProofService,
			Subsystem: SubsystemZK,
			Name:      string(MetricRequestsUnauthorized),
			Help:      "Total number of requests rejected for missing or invalid authorization",
		}),
		MetricRequestsTooLarge: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: NamespaceProofService,
			Subsystem: SubsystemZK,
			Name:      string(MetricRequestsTooLarge),
			Help:      "Total number of requests rejected for exceeding the max body size",
		}),
	}

	gauges = map[MetricName]prometheus.Gauge{
		MetricProofsInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: NamespaceProofService,
			Subsystem: SubsystemZK,
			Name:      string(MetricProofsInFlight),
			Help:      "Number of proof generations currently in progress",
		}),
	}

	histograms = map[MetricName]prometheus.Histogram{
		MetricProofDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: NamespaceProofService,
			Subsystem: SubsystemZK,
			Name:      string(MetricProofDuration),
			Help:      "Duration of proof generation in seconds",
			Buckets:   []float64{1, 5, 10, 30, 60, 120, 300},
		}),
	}

	registerOnce sync.Once
)

// NewMetrics creates and registers Prometheus metrics.
func NewMetrics() *Metrics {
	registerOnce.Do(func() {
		for _, counter := range counters {
			prometheus.MustRegister(counter)
		}
		for _, histogram := range histograms {
			prometheus.MustRegister(histogram)
		}
		for _, gauge := range gauges {
			prometheus.MustRegister(gauge)
		}
	})
	return &Metrics{}
}

// IncrCounter increments the specified counter metric.
func (m *Metrics) IncrCounter(name MetricName) {
	if counter, ok := counters[name]; ok {
		counter.Inc()
	}
}

// ObserveHistogram records a value in the specified histogram metric.
func (m *Metrics) ObserveHistogram(name MetricName, value float64) {
	if hist, ok := histograms[name]; ok {
		hist.Observe(value)
	}
}

// IncrGauge increments the specified gauge metric.
func (m *Metrics) IncrGauge(name MetricName) {
	if gauge, ok := gauges[name]; ok {
		gauge.Inc()
	}
}

// DecrGauge decrements the specified gauge metric.
func (m *Metrics) DecrGauge(name MetricName) {
	if gauge, ok := gauges[name]; ok {
		gauge.Dec()
	}
}

// RegisterHandlers registers the /metrics endpoint on the provided mux.
func RegisterHandlers(mux *http.ServeMux) {
	mux.Handle("/metrics", promhttp.Handler())
}
