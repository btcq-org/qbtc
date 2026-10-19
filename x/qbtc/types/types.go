package types

import (
	"bytes"
	"compress/gzip"
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
	gw.ModTime = time.Time{} // zero value -> fixed mtime
	gw.Name = ""
	gw.Comment = ""
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

