package types

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"testing"

	protoio "github.com/cosmos/gogoproto/io"
	"github.com/stretchr/testify/require"
)

// genesisUtxoFile encodes n UTXOs the way genesis.bin holds them.
func genesisUtxoFile(t *testing.T, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := protoio.NewDelimitedWriter(&buf)
	for i := range n {
		utxo := UTXO{
			Txid:           fmt.Sprintf("%064x", i+1),
			Vout:           uint32(i % 3),
			Amount:         uint64(1000 + i),
			EntitledAmount: uint64(1000 + i),
			ScriptPubKey:   &ScriptPubKeyResult{Address: fmt.Sprintf("addr%d", i), Type: "pubkeyhash"},
			BlockHeight:    uint64(i),
		}
		require.NoError(t, w.WriteMsg(&utxo))
	}
	return buf.Bytes()
}

// splitInMemory splits file into chunks of perChunk UTXOs and returns their bytes and hashes.
func splitInMemory(t *testing.T, file []byte, perChunk int) ([][]byte, [][]byte, error) {
	t.Helper()
	var chunks []*bytes.Buffer
	hashes, err := splitUtxoChunks(bytes.NewReader(file), perChunk, func(index uint64) (io.Writer, func() error, error) {
		require.Equal(t, uint64(len(chunks)), index)
		buf := &bytes.Buffer{}
		chunks = append(chunks, buf)
		return buf, func() error { return nil }, nil
	})
	out := make([][]byte, len(chunks))
	for i, c := range chunks {
		out[i] = c.Bytes()
	}
	return out, hashes, err
}

func TestSplitUtxoChunks(t *testing.T) {
	file := genesisUtxoFile(t, 7)

	chunks, hashes, err := splitInMemory(t, file, 3)
	require.NoError(t, err)
	require.Len(t, chunks, 3, "7 UTXOs in chunks of 3")
	require.Len(t, hashes, 3)
	for i := range chunks {
		sum := sha256.Sum256(chunks[i])
		require.Equal(t, sum[:], hashes[i], "chunk %d", i)
	}
	// The chunks together hold the same records as the file.
	require.Equal(t, file, bytes.Join(chunks, nil))

	// The split is deterministic.
	_, again, err := splitInMemory(t, file, 3)
	require.NoError(t, err)
	require.Equal(t, hashes, again)

	// A file that divides evenly gets no empty trailing chunk.
	chunks, _, err = splitInMemory(t, genesisUtxoFile(t, 6), 3)
	require.NoError(t, err)
	require.Len(t, chunks, 2)

	// An empty file has no chunks.
	chunks, hashes, err = splitInMemory(t, nil, 3)
	require.NoError(t, err)
	require.Empty(t, chunks)
	require.Empty(t, hashes)
}

func TestSplitUtxoChunks_TruncatedFile(t *testing.T) {
	file := genesisUtxoFile(t, 4)
	_, _, err := splitInMemory(t, file[:len(file)-5], 2)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestUtxoChunkHashesMatchesSplit(t *testing.T) {
	file := genesisUtxoFile(t, 5)
	want, err := SplitUtxoChunks(bytes.NewReader(file), func(uint64) (io.Writer, func() error, error) {
		return io.Discard, func() error { return nil }, nil
	})
	require.NoError(t, err)
	got, err := UtxoChunkHashes(bytes.NewReader(file))
	require.NoError(t, err)
	require.Equal(t, want, got)
	require.Len(t, got, 1, "5 UTXOs fit in one production chunk")
}

func TestReadUtxoChunk(t *testing.T) {
	chunks, hashes, err := splitInMemory(t, genesisUtxoFile(t, 4), 4)
	require.NoError(t, err)
	chunk, hash := chunks[0], hashes[0]

	var read []UTXO
	require.NoError(t, ReadUtxoChunk(bytes.NewReader(chunk), hash, func(u UTXO) error {
		read = append(read, u)
		return nil
	}))
	require.Len(t, read, 4)
	require.Equal(t, fmt.Sprintf("%064x", 1), read[0].Txid)

	t.Run("hash mismatch", func(t *testing.T) {
		other := sha256.Sum256([]byte("other"))
		err := ReadUtxoChunk(bytes.NewReader(chunk), other[:], func(UTXO) error { return nil })
		require.ErrorContains(t, err, "genesis expects")
	})
	t.Run("altered record", func(t *testing.T) {
		altered := bytes.Clone(chunk)
		altered[len(altered)-1] ^= 0x01
		err := ReadUtxoChunk(bytes.NewReader(altered), hash, func(UTXO) error { return nil })
		require.Error(t, err)
	})
	t.Run("truncated chunk", func(t *testing.T) {
		err := ReadUtxoChunk(bytes.NewReader(chunk[:len(chunk)-3]), hash, func(UTXO) error { return nil })
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})
	t.Run("chunk cut at a record boundary", func(t *testing.T) {
		halves, halfHashes, err := splitInMemory(t, genesisUtxoFile(t, 4), 2)
		require.NoError(t, err)
		// The first half is a valid encoding on its own but is not the chunk the hash names.
		err = ReadUtxoChunk(bytes.NewReader(halves[0]), hash, func(UTXO) error { return nil })
		require.ErrorContains(t, err, "genesis expects")
		require.NotEqual(t, hash, halfHashes[0])
	})
}
