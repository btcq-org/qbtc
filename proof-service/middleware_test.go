package proofservice

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/btcq-org/qbtc/proof-service/metrics"
	"github.com/rs/zerolog"
)

func testMetrics() *metrics.Metrics { return metrics.NewMetrics() }

func testLogger() zerolog.Logger { return zerolog.Nop() }

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func TestChainOrdering(t *testing.T) {
	var order []string
	mw := func(name string) middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name)
				next.ServeHTTP(w, r)
			})
		}
	}
	h := chain(okHandler(), mw("first"), mw("second"), mw("third"))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	got := strings.Join(order, ",")
	if got != "first,second,third" {
		t.Fatalf("expected outermost-first ordering, got %q", got)
	}
}

func TestRecoverMiddleware(t *testing.T) {
	panicky := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})
	h := chain(panicky, recoverMiddleware(testLogger()))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/prove", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on panic, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "INTERNAL") {
		t.Fatalf("expected INTERNAL error body, got %q", rec.Body.String())
	}
}

func TestMaxBytesMiddleware_ContentLength(t *testing.T) {
	h := chain(okHandler(), maxBytesMiddleware(10, testMetrics()))

	req := httptest.NewRequest(http.MethodPost, "/prove", strings.NewReader("this body is definitely longer than ten bytes"))
	req.ContentLength = 45
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for oversized Content-Length, got %d", rec.Code)
	}
}

func TestMaxBytesMiddleware_StreamingBodyFailsDownstream(t *testing.T) {
	// Handler reads the whole body; MaxBytesReader must surface an error once
	// the limit is exceeded even when Content-Length is not set.
	var readErr error
	reader := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, readErr = io.ReadAll(r.Body)
	})
	h := chain(reader, maxBytesMiddleware(10, testMetrics()))

	req := httptest.NewRequest(http.MethodPost, "/prove", strings.NewReader("way more than ten bytes of data"))
	req.ContentLength = -1 // unknown length -> skip the fast path
	h.ServeHTTP(httptest.NewRecorder(), req)

	if readErr == nil {
		t.Fatal("expected body read to fail once the byte limit was exceeded")
	}
}

func TestConcurrencyMiddleware_ShedsLoadWhenFull(t *testing.T) {
	slots := make(chan struct{}, 1)

	release := make(chan struct{})
	entered := make(chan struct{})
	blocking := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusOK)
	})
	h := chain(blocking, concurrencyMiddleware(slots, testMetrics()))

	// First request occupies the only slot and blocks inside the handler.
	firstDone := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/prove", nil))
		firstDone <- rec.Code
	}()
	<-entered

	// Second request finds no free slot and must be shed immediately.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/prove", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 while slot busy, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header on 503")
	}

	// Release the first request; the slot frees and a later request succeeds.
	close(release)
	if code := <-firstDone; code != http.StatusOK {
		t.Fatalf("first request should have succeeded, got %d", code)
	}
	// Use a fresh non-blocking handler over the same slot channel to confirm
	// the slot was released.
	h2 := chain(okHandler(), concurrencyMiddleware(slots, testMetrics()))
	rec = httptest.NewRecorder()
	h2.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/prove", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 after slot freed, got %d", rec.Code)
	}
}

func TestConcurrencyMiddleware_ReleasesSlotOnPanic(t *testing.T) {
	slots := make(chan struct{}, 1)
	panicky := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") })
	// recover wraps concurrency so the deferred slot release still runs.
	h := chain(panicky, recoverMiddleware(testLogger()), concurrencyMiddleware(slots, testMetrics()))

	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/prove", nil))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("iteration %d: expected 500, got %d", i, rec.Code)
		}
	}
	// If the slot leaked, this non-blocking send would fail.
	select {
	case slots <- struct{}{}:
	default:
		t.Fatal("proving slot leaked after panic")
	}
}

func TestClientIP(t *testing.T) {
	tests := map[string]string{
		"1.2.3.4:5678": "1.2.3.4",
		"[::1]:9090":   "::1",
		"noport":       "noport",
	}
	for remote, want := range tests {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = remote
		if got := clientIP(req); got != want {
			t.Fatalf("clientIP(%q) = %q, want %q", remote, got, want)
		}
	}
}

// Guard against a data race in the slot accounting under -race.
func TestConcurrencyMiddleware_Race(t *testing.T) {
	slots := make(chan struct{}, 4)
	h := chain(okHandler(), concurrencyMiddleware(slots, testMetrics()))

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/prove", nil))
			if rec.Code != http.StatusOK && rec.Code != http.StatusServiceUnavailable {
				t.Errorf("unexpected status %d", rec.Code)
			}
		}()
	}
	wg.Wait()
}
