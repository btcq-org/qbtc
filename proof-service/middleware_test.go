package proofservice

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/btcq-org/qbtc/proof-service/metrics"
	"github.com/labstack/echo/v4"
	echomw "github.com/labstack/echo/v4/middleware"
)

func testMetrics() *metrics.Metrics { return metrics.NewMetrics() }

func post(e *echo.Echo) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/prove", nil))
	return rec
}

func TestConcurrencyMiddleware_ShedsLoadWhenFull(t *testing.T) {
	slots := make(chan struct{}, 1)
	release := make(chan struct{})
	entered := make(chan struct{})

	e := echo.New()
	e.POST("/prove", func(c echo.Context) error {
		close(entered)
		<-release
		return c.NoContent(http.StatusOK)
	}, concurrencyMiddleware(slots, testMetrics()))

	// First request occupies the only slot and blocks inside the handler.
	firstDone := make(chan int, 1)
	go func() {
		rec := post(e)
		firstDone <- rec.Code
	}()
	<-entered

	// Second request finds no free slot and must be shed immediately.
	rec := post(e)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 while slot busy, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header on 503")
	}

	// Release the first request; its deferred cleanup must free the slot.
	close(release)
	if code := <-firstDone; code != http.StatusOK {
		t.Fatalf("first request should have succeeded, got %d", code)
	}
	if len(slots) != 0 {
		t.Fatalf("slot not released: len(slots) = %d", len(slots))
	}
}

func TestConcurrencyMiddleware_ReleasesSlotOnPanic(t *testing.T) {
	slots := make(chan struct{}, 1)

	e := echo.New()
	e.Use(echomw.Recover()) // recover unwinds through the concurrency defer
	e.POST("/prove", func(echo.Context) error {
		panic("boom")
	}, concurrencyMiddleware(slots, testMetrics()))

	for i := 0; i < 3; i++ {
		rec := post(e)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("iteration %d: expected 500, got %d", i, rec.Code)
		}
	}
	if len(slots) != 0 {
		t.Fatalf("proving slot leaked after panic: len(slots) = %d", len(slots))
	}
}

// Exercise the slot accounting concurrently so -race can catch a data race.
func TestConcurrencyMiddleware_Race(t *testing.T) {
	slots := make(chan struct{}, 4)

	e := echo.New()
	e.POST("/prove", func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	}, concurrencyMiddleware(slots, testMetrics()))

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := post(e)
			if rec.Code != http.StatusOK && rec.Code != http.StatusServiceUnavailable {
				t.Errorf("unexpected status %d", rec.Code)
			}
		}()
	}
	wg.Wait()
}
