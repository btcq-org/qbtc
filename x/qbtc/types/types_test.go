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

func TestGzipUnzip_ExceedsMaxDecompressedSize(t *testing.T) {
	// Create data larger than MaxDecompressedBlockSize
	oversized := make([]byte, MaxDecompressedBlockSize+1)
	for i := range oversized {
		oversized[i] = 'A'
	}

	compressed, err := GzipDeterministic(oversized, gzip.BestSpeed)
	if err != nil {
		t.Fatalf("failed to compress oversized data: %v", err)
	}

	_, err = GzipUnzip(compressed)
	if err == nil {
		t.Fatal("expected error when decompressed data exceeds MaxDecompressedBlockSize, got nil")
	}

	// Data exactly at the limit should succeed
	exact := make([]byte, MaxDecompressedBlockSize)
	for i := range exact {
		exact[i] = 'B'
	}

	compressedExact, err := GzipDeterministic(exact, gzip.BestSpeed)
	if err != nil {
		t.Fatalf("failed to compress exact-size data: %v", err)
	}

	out, err := GzipUnzip(compressedExact)
	if err != nil {
		t.Fatalf("expected no error for data at limit, got: %v", err)
	}
	if len(out) != MaxDecompressedBlockSize {
		t.Fatalf("expected output length %d, got %d", MaxDecompressedBlockSize, len(out))
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
