package types

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	protoio "github.com/cosmos/gogoproto/io"
)

const (
	// UtxosPerChunk is the number of UTXOs in each genesis UTXO chunk; the
	// last chunk may hold fewer. The node loads one chunk per block.
	UtxosPerChunk = 1_000_000

	// MaxUtxoMessageSize bounds one delimited UTXO record in genesis.bin and in
	// a chunk file.
	MaxUtxoMessageSize = 50 * 1024 * 1024
)

// utxoRecordReader reads the length-delimited UTXO records of genesis.bin and
// of a chunk file. gogoproto's delimited reader returns io.EOF when the input
// ends right after a record's length prefix, the same error as a clean end, so
// a file cut there would read as complete. Here only an end before a length
// prefix is io.EOF; an end anywhere inside a record is io.ErrUnexpectedEOF.
type utxoRecordReader struct {
	r   *bufio.Reader
	buf []byte
}

func newUtxoRecordReader(r io.Reader) *utxoRecordReader {
	return &utxoRecordReader{r: bufio.NewReader(r)}
}

// read reads the next record into utxo, replacing its content.
func (rr *utxoRecordReader) read(utxo *UTXO) error {
	length, err := binary.ReadUvarint(rr.r)
	if err != nil {
		// io.EOF before the prefix, io.ErrUnexpectedEOF inside it.
		return err
	}
	if length > MaxUtxoMessageSize {
		return fmt.Errorf("UTXO record of %d bytes exceeds %d", length, MaxUtxoMessageSize)
	}
	if uint64(cap(rr.buf)) < length {
		rr.buf = make([]byte, length)
	}
	buf := rr.buf[:length]
	if _, err := io.ReadFull(rr.r, buf); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	utxo.Reset()
	return utxo.Unmarshal(buf)
}

// ChunkWriterFunc returns the writer for chunk index and a function that
// finishes it once every record is written.
type ChunkWriterFunc func(index uint64) (w io.Writer, finish func() error, err error)

// SplitUtxoChunks reads length-delimited UTXO records from r, the format of
// genesis.bin, and re-encodes them in chunks of UtxosPerChunk, writing each
// chunk to the writer open returns. It returns the SHA-256 of each chunk's
// bytes, which is what genesis utxo_chunk_hashes holds. The encoding is
// deterministic, so the same genesis.bin always gives the same chunks. A
// truncated record is an error, not the end of the file.
func SplitUtxoChunks(r io.Reader, open ChunkWriterFunc) ([][]byte, error) {
	return splitUtxoChunks(r, UtxosPerChunk, open)
}

func splitUtxoChunks(r io.Reader, utxosPerChunk int, open ChunkWriterFunc) ([][]byte, error) {
	reader := newUtxoRecordReader(r)
	var hashes [][]byte
	var utxo UTXO
	readErr := reader.read(&utxo)
	for index := uint64(0); readErr != io.EOF; index++ {
		if readErr != nil {
			return nil, fmt.Errorf("read genesis UTXO: %w", readErr)
		}
		w, finish, err := open(index)
		if err != nil {
			return nil, fmt.Errorf("open UTXO chunk %d: %w", index, err)
		}
		hash := sha256.New()
		buffered := bufio.NewWriter(io.MultiWriter(w, hash))
		writer := protoio.NewDelimitedWriter(buffered)
		for n := 0; n < utxosPerChunk && readErr == nil; n++ {
			if err := writer.WriteMsg(&utxo); err != nil {
				return nil, fmt.Errorf("write UTXO chunk %d: %w", index, err)
			}
			readErr = reader.read(&utxo)
		}
		if readErr != nil && readErr != io.EOF {
			return nil, fmt.Errorf("read genesis UTXO: %w", readErr)
		}
		if err := buffered.Flush(); err != nil {
			return nil, fmt.Errorf("write UTXO chunk %d: %w", index, err)
		}
		if err := finish(); err != nil {
			return nil, fmt.Errorf("finish UTXO chunk %d: %w", index, err)
		}
		hashes = append(hashes, hash.Sum(nil))
	}
	return hashes, nil
}

// UtxoChunkHashes returns the chunk hashes for the genesis.bin content in r,
// without writing the chunks.
func UtxoChunkHashes(r io.Reader) ([][]byte, error) {
	return SplitUtxoChunks(r, func(uint64) (io.Writer, func() error, error) {
		return io.Discard, func() error { return nil }, nil
	})
}

// ReadUtxoChunk reads the UTXO records of one chunk from r and passes each to
// fn. It fails unless the chunk's bytes hash to expectedHash, so the caller
// must not commit what fn did before ReadUtxoChunk returns nil. A truncated
// record is an error, not the end of the chunk.
func ReadUtxoChunk(r io.Reader, expectedHash []byte, fn func(UTXO) error) error {
	hash := sha256.New()
	reader := newUtxoRecordReader(io.TeeReader(r, hash))
	for {
		var utxo UTXO
		err := reader.read(&utxo)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read UTXO: %w", err)
		}
		if err := fn(utxo); err != nil {
			return err
		}
	}
	if got := hash.Sum(nil); string(got) != string(expectedHash) {
		return fmt.Errorf("chunk hashes to %x, genesis expects %x", got, expectedHash)
	}
	return nil
}
