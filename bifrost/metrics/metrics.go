package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
}

type MetricName string

const (
	MetricNameProcessedBlocks MetricName = "processed_blocks"
	MetricNameAttestedBlocks  MetricName = "attested_blocks"
)

func (m MetricName) String() string {
	return string(m)
}

const (
	NamespaceBifrost = "bifrost"
	SubsystemP2P     = "p2p"
	SubsystemBitcoin = "bitcoin"
)

var (
	counters = map[MetricName]prometheus.Counter{
		MetricNameProcessedBlocks: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: NamespaceBifrost,
			Subsystem: SubsystemBitcoin,
			Name:      MetricNameProcessedBlocks.String(),
			Help:      "Number of processed blocks",
		}),
		MetricNameAttestedBlocks: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: NamespaceBifrost,
			Subsystem: SubsystemP2P,
			Name:      MetricNameAttestedBlocks.String(),
			Help:      "Number of attested blocks",
		}),
	}
)

func NewMetrics() *Metrics {
	for _, counter := range counters {
		prometheus.Register(counter)
	}
	return &Metrics{}
}

func (m *Metrics) IncrCounter(name MetricName) {
	if counter, ok := counters[name]; ok {
		counter.Inc()
	}
}

func RegisterHandlers(mux *http.ServeMux) {
	mux.Handle("/metrics", promhttp.Handler())
}
