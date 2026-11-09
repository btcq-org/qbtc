package module

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// genesisCoinbaseTxid is the coinbase of Bitcoin's genesis block, which can
// never be spent. Its UTXO is loaded as already claimed.
const genesisCoinbaseTxid = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

// UtxoLoader loads the genesis UTXO snapshot. At InitChain it splits
// config/genesis.bin into chunk files under utxo_chunks/ and checks them
// against the genesis utxo_chunk_hashes; then each block loads the next chunk
// into state, checking its hash again. Neither genesis.bin nor the chunk files
// are deleted: a block executed again after a crash, or by optimistic
// execution, reads its chunk again. Operators can delete them once the
// snapshot is loaded.
type UtxoLoader struct {
	DataDir string
}

func NewUtxoLoader(dataDir string) UtxoLoader {
	return UtxoLoader{DataDir: dataDir}
}

func (ul UtxoLoader) genesisFile() string {
	return filepath.Join(ul.DataDir, "config", "genesis.bin")
}

func (ul UtxoLoader) chunkFile(index uint64) string {
	return filepath.Join(ul.DataDir, "utxo_chunks", fmt.Sprintf("genesis_chunk_%d.bin", index))
}

// PrepareUtxoChunks makes the chunk files match expected, the genesis
// utxo_chunk_hashes. Chunk files that already match, as after a replayed
// InitChain, are kept; otherwise genesis.bin is split again. A genesis.bin
// without hashes in genesis is an error, so a snapshot is never loaded
// unchecked.
func (ul UtxoLoader) PrepareUtxoChunks(ctx sdk.Context, expected [][]byte) error {
	if len(expected) == 0 {
		if _, err := os.Stat(ul.genesisFile()); err == nil {
			return fmt.Errorf("%s is present but genesis has no utxo_chunk_hashes", ul.genesisFile())
		}
		return nil
	}
	if err := ul.checkChunkFiles(expected); err == nil {
		ctx.Logger().Info("genesis UTXO chunk files already match genesis", "chunks", len(expected))
		return nil
	}

	f, err := os.Open(ul.genesisFile())
	if err != nil {
		return fmt.Errorf("genesis has %d utxo_chunk_hashes: %w", len(expected), err)
	}
	defer f.Close()
	if err := os.MkdirAll(filepath.Dir(ul.chunkFile(0)), 0o755); err != nil {
		return err
	}
	ctx.Logger().Info("splitting genesis UTXO file", "file", ul.genesisFile())
	hashes, err := types.SplitUtxoChunks(bufio.NewReader(f), ul.createChunkFile)
	if err != nil {
		return err
	}
	if len(hashes) != len(expected) {
		return fmt.Errorf("%s splits into %d chunks, genesis has %d utxo_chunk_hashes", ul.genesisFile(), len(hashes), len(expected))
	}
	for i := range hashes {
		if !bytes.Equal(hashes[i], expected[i]) {
			return fmt.Errorf("genesis UTXO chunk %d hashes to %x, genesis expects %x", i, hashes[i], expected[i])
		}
	}
	ctx.Logger().Info("genesis UTXO file split", "chunks", len(hashes))
	return nil
}

// createChunkFile writes chunk index to a temporary file and renames it into
// place when it is complete, so a crash never leaves a partial chunk file.
func (ul UtxoLoader) createChunkFile(index uint64) (io.Writer, func() error, error) {
	path := ul.chunkFile(index)
	tmp, err := os.Create(path + ".tmp")
	if err != nil {
		return nil, nil, err
	}
	finish := func() error {
		if err := tmp.Sync(); err != nil {
			return errors.Join(err, tmp.Close())
		}
		if err := tmp.Close(); err != nil {
			return err
		}
		return os.Rename(tmp.Name(), path)
	}
	return tmp, finish, nil
}

// checkChunkFiles returns nil if every chunk file exists and matches its hash.
func (ul UtxoLoader) checkChunkFiles(expected [][]byte) error {
	for i, hash := range expected {
		f, err := os.Open(ul.chunkFile(uint64(i)))
		if err != nil {
			return err
		}
		err = types.ReadUtxoChunk(bufio.NewReader(f), hash, func(types.UTXO) error { return nil })
		f.Close()
		if err != nil {
			return fmt.Errorf("chunk %d: %w", i, err)
		}
	}
	return nil
}

// LoadNextUtxoChunk loads the next genesis UTXO chunk into state, if any is
// left. Any failure, including a missing file, a truncated record or a hash
// mismatch, is returned: the block then fails, so no write of a bad chunk is
// committed and the node stops instead of diverging from the other nodes.
func (ul UtxoLoader) LoadNextUtxoChunk(ctx sdk.Context, k *keeper.Keeper) error {
	index, hash, done, err := k.NextUtxoChunk(ctx)
	if err != nil || done {
		return err
	}
	path := ul.chunkFile(index)
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("genesis UTXO chunk %d: %w", index, err)
	}
	defer f.Close()

	ctx.Logger().Info("loading genesis UTXO chunk", "chunk", index, "file", path)
	loaded := 0
	err = types.ReadUtxoChunk(bufio.NewReader(f), hash, func(utxo types.UTXO) error {
		if utxo.Txid == genesisCoinbaseTxid {
			utxo.EntitledAmount = 0
		}
		loaded++
		return k.Utxoes.Set(ctx, utxo.GetKey(), utxo)
	})
	if err != nil {
		return fmt.Errorf("genesis UTXO chunk %d (%s): %w", index, path, err)
	}
	if err := k.MarkUtxoChunkLoaded(ctx, index); err != nil {
		return err
	}
	ctx.Logger().Info("loaded genesis UTXO chunk", "chunk", index, "utxos", loaded)
	return nil
}
