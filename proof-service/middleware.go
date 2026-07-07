package proofservice

import (
	"net/http"

	"github.com/btcq-org/qbtc/proof-service/metrics"
	"github.com/labstack/echo/v4"
	echomw "github.com/labstack/echo/v4/middleware"
	"github.com/rs/zerolog"
)

// requestLogger bridges echo's access log into the service's zerolog logger,
// emitting one structured line per request.
func requestLogger(logger zerolog.Logger) echo.MiddlewareFunc {
	return echomw.RequestLoggerWithConfig(echomw.RequestLoggerConfig{
		LogMethod:    true,
		LogURI:       true,
		LogStatus:    true,
		LogLatency:   true,
		LogRemoteIP:  true,
		LogRequestID: true,
		LogError:     true,
		LogValuesFunc: func(_ echo.Context, v echomw.RequestLoggerValues) error {
			evt := logger.Info()
			if v.Error != nil {
				evt = logger.Error().Err(v.Error)
			}
			evt.
				Str("request_id", v.RequestID).
				Str("method", v.Method).
				Str("uri", v.URI).
				Str("remote", v.RemoteIP).
				Int("status", v.Status).
				Dur("duration", v.Latency).
				Msg("handled request")
			return nil
		},
	})
}

// concurrencyMiddleware bounds how many downstream handlers run at once using a
// slot channel. When no slot is free the request is rejected immediately with
// 503 rather than queued, so an overloaded service sheds load instead of
// building an unbounded backlog of expensive proving work. The deferred slot
// release runs even if the handler panics (echo's Recover unwinds through it).
func concurrencyMiddleware(slots chan struct{}, m *metrics.Metrics) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
				m.IncrGauge(metrics.MetricProofsInFlight)
				defer m.DecrGauge(metrics.MetricProofsInFlight)
				return next(c)
			default:
				m.IncrCounter(metrics.MetricRequestsBusy)
				c.Response().Header().Set("Retry-After", "30")
				return c.JSON(http.StatusServiceUnavailable, echo.Map{
					"error": "all proving slots are busy, retry later",
					"code":  "BUSY",
				})
			}
		}
	}
}
