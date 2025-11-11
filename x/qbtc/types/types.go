package types

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"time"
)

// GzipDeterministic sets a fixed header (zero ModTime, empty Name/Comment)
// and uses the specified compression level.
func GzipDeterministic(data []byte, level int) ([]byte, error) {
	var buf bytes.Buffer
	gw, err := gzip.NewWriterLevel(&buf, level)
	if err != nil {
		return nil, err
	}
	// Make gzip header deterministic
	gw.Header.ModTime = time.Time{} // zero value -> fixed mtime
	gw.Header.Name = ""
	gw.Header.Comment = ""
	defer func() {
		_ = gw.Close()
	}()
	if _, err := gw.Write(data); err != nil {
		return nil, err
	}

	if err := gw.Flush(); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// GzipUnzip decompresses gzip-compressed bytes and returns raw bytes.
func GzipUnzip(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gzip new reader: %w", err)
	}
	defer func() {
		_ = r.Close()
	}()
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("gzip read: %w", err)
	}
	return out, nil
}
