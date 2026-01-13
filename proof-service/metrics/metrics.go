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

// RegisterHandlers registers the /metrics endpoint on the provided mux.
func RegisterHandlers(mux *http.ServeMux) {
	mux.Handle("/metrics", promhttp.Handler())
}
