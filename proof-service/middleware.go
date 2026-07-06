package proofservice

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/btcq-org/qbtc/proof-service/metrics"
	"github.com/rs/zerolog"
)

// middleware decorates an http.Handler with a cross-cutting concern.
type middleware func(http.Handler) http.Handler

// chain applies the given middlewares to h so that the first listed runs
// outermost (closest to the client) and the last runs innermost (closest to
// the handler).
func chain(h http.Handler, mw ...middleware) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

// statusRecorder captures the response status code for access logging.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// recoverMiddleware converts a panic in any downstream handler into a 500
// response and a log line instead of crashing the process.
func recoverMiddleware(logger zerolog.Logger) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logger.Error().
						Interface("panic", rec).
						Str("path", r.URL.Path).
						Msg("recovered from panic in handler")
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`{"error":"internal server error","code":"INTERNAL"}`))
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// requestLogMiddleware assigns a request ID and logs method, path, status and
// latency for every request.
func requestLogMiddleware(logger zerolog.Logger) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			reqID := newRequestID()
			w.Header().Set("X-Request-ID", reqID)

			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)

			logger.Info().
				Str("request_id", reqID).
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Str("remote", clientIP(r)).
				Int("status", rec.status).
				Dur("duration", time.Since(start)).
				Msg("handled request")
		})
	}
}

// maxBytesMiddleware caps the request body size. Bodies larger than limit cause
// the downstream Body.Read to fail; this also short-circuits an obviously
// oversized Content-Length up front.
func maxBytesMiddleware(limit int64, m *metrics.Metrics) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > limit {
				m.IncrCounter(metrics.MetricRequestsTooLarge)
				writeJSONError(w, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", "request body exceeds the maximum allowed size")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
			next.ServeHTTP(w, r)
		})
	}
}

// concurrencyMiddleware bounds how many downstream handlers run at once using a
// slot channel. When no slot is free the request is rejected immediately with
// 503 rather than queued, so an overloaded service sheds load instead of
// building an unbounded backlog of expensive proving work.
func concurrencyMiddleware(slots chan struct{}, m *metrics.Metrics) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
				m.IncrGauge(metrics.MetricProofsInFlight)
				defer m.DecrGauge(metrics.MetricProofsInFlight)
				next.ServeHTTP(w, r)
			default:
				m.IncrCounter(metrics.MetricRequestsBusy)
				w.Header().Set("Retry-After", "30")
				writeJSONError(w, http.StatusServiceUnavailable, "BUSY", "all proving slots are busy, retry later")
			}
		})
	}
}

// clientIP returns the remote host without the port. It deliberately uses the
// transport-level address and not X-Forwarded-For, which is client-spoofable;
// operators terminating TLS at a trusted proxy should set the address there.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "req"
	}
	return hex.EncodeToString(b[:])
}

// writeJSONError writes a minimal JSON error body. It avoids json.Marshal so it
// can be used from middleware that must not fail.
func writeJSONError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	var sb strings.Builder
	sb.WriteString(`{"error":`)
	sb.WriteString(quoteJSON(msg))
	sb.WriteString(`,"code":`)
	sb.WriteString(quoteJSON(code))
	sb.WriteString(`}`)
	_, _ = w.Write([]byte(sb.String()))
}

// quoteJSON returns s as a JSON string literal, escaping the characters that
// can appear in our fixed error strings.
func quoteJSON(s string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		default:
			sb.WriteRune(r)
		}
	}
	sb.WriteByte('"')
	return sb.String()
}
