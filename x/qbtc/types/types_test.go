package types

import (
	"bytes"
	"compress/gzip"
	"fmt"
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
			out, err := GzipUnzip(a)
			if err != nil {
				t.Fatalf("GzipUnzip failed: %v", err)
			}
			if !bytes.Equal(out, data) {
				t.Fatalf("round-trip data mismatch: got %q want %q", out, data)
			}
		})
	}
}

func TestGzipUnzip_EmptyAndInvalid(t *testing.T) {
	t.Run("empty_input", func(t *testing.T) {
		out, err := GzipUnzip(nil)
		if err != nil {
			t.Fatalf("expected no error for empty input, got: %v", err)
		}
		if len(out) != 0 {
			t.Fatalf("expected empty output for empty input, got length %d", len(out))
		}
	})

	t.Run("invalid_input", func(t *testing.T) {
		_, err := GzipUnzip([]byte("not a gzip stream"))
		if err == nil {
			t.Fatalf("expected error for invalid gzip data, got nil")
		}
	})
}
