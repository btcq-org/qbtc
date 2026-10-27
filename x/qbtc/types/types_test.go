package types

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"testing"
)

func TestGzipDeterministic_SameOutputAndRoundTrip(t *testing.T) {
	data := []byte("example data for deterministic gzip")
	levels := []int{gzip.BestSpeed, gzip.DefaultCompression, gzip.BestCompression}

	for _, lvl := range levels {
		name := fmt.Sprintf("level_%d", lvl)
		t.Run(name, func(t *testing.T) {
			a, err := GzipDeterministic(data, lvl)
			if err != nil {
				t.Fatalf("first compress returned error: %v", err)
			}
			if len(a) == 0 {
				t.Fatalf("first compress returned empty output")
			}

			b, err := GzipDeterministic(data, lvl)
			if err != nil {
				t.Fatalf("second compress returned error: %v", err)
			}

			if !bytes.Equal(a, b) {
				t.Fatalf("outputs differ for same input/level: len(a)=%d len(b)=%d", len(a), len(b))
			}

			// Round-trip decompress
			r, err := gzip.NewReader(bytes.NewReader(a))
			if err != nil {
				t.Fatalf("gzip reader failed: %v", err)
			}
			out, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("gzip read failed: %v", err)
			}
			if !bytes.Equal(out, data) {
				t.Fatalf("round-trip data mismatch: got %q want %q", out, data)
			}
		})
	}
}
