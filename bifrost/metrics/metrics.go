package metrics

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
}

type MetricName string

const (
	MetricNameProcessedBlocks MetricName = "processed_blocks"
	MetricNameAttestedBlocks  MetricName = "attested_blocks"
	MetricNameValidatorPeers  MetricName = "validator_peers"
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
	gauges = map[MetricName]prometheus.Gauge{
		MetricNameValidatorPeers: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: NamespaceBifrost,
			Subsystem: SubsystemP2P,
			Name:      MetricNameValidatorPeers.String(),
			Help:      "Number of known validator peers",
		}),
	}
)

var registerOnce sync.Once

func NewMetrics() *Metrics {
	registerOnce.Do(func() {
		for _, counter := range counters {
			_ = prometheus.Register(counter)
		}
		for _, gauge := range gauges {
			_ = prometheus.Register(gauge)
		}
	})
	return &Metrics{}
}

func (m *Metrics) IncrCounter(name MetricName) {
	if counter, ok := counters[name]; ok {
		counter.Inc()
	}
}

func (m *Metrics) SetGauge(name MetricName, value float64) {
	if gauge, ok := gauges[name]; ok {
		gauge.Set(value)
	}
}

func RegisterHandlers(mux *http.ServeMux) {
	mux.Handle("/metrics", promhttp.Handler())
}
