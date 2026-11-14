package module

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	addresscodec "github.com/cosmos/cosmos-sdk/codec/address"
	"github.com/cosmos/cosmos-sdk/runtime"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	"github.com/cosmos/cosmos-sdk/testutil"
	sdk "github.com/cosmos/cosmos-sdk/types"
	moduletestutil "github.com/cosmos/cosmos-sdk/types/module/testutil"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"
	protoio "github.com/cosmos/gogoproto/io"
	"github.com/stretchr/testify/require"

	"github.com/btcq-org/qbtc/common"
	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	"github.com/btcq-org/qbtc/x/qbtc/types"
)

func newLoaderTestKeeper(t *testing.T) (sdk.Context, *keeper.Keeper) {
	t.Helper()
	encCfg := moduletestutil.MakeTestEncodingConfig(AppModule{})
	storeKey := storetypes.NewKVStoreKey(types.StoreKey)
	transientKey := storetypes.NewTransientStoreKey("transient_test")
	ctx := testutil.DefaultContextWithDB(t, storeKey, transientKey).Ctx
	k := keeper.NewKeeper(runtime.NewKVStoreService(storeKey), runtime.NewTransientStoreService(transientKey), encCfg.Codec,
		addresscodec.NewBech32Codec(common.AccountAddressPrefix), nil, nil, nil, govtypes.ModuleName)
	return ctx, k
}

// utxoRecords encodes n UTXOs, with txids starting at first, in the
// genesis.bin format.
func utxoRecords(t *testing.T, first, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := protoio.NewDelimitedWriter(&buf)
	for i := first; i < first+n; i++ {
		utxo := types.UTXO{
			Txid:           fmt.Sprintf("%064x", i),
			Amount:         uint64(1000 + i),
			EntitledAmount: uint64(1000 + i),
			ScriptPubKey:   &types.ScriptPubKeyResult{Address: fmt.Sprintf("addr%d", i)},
		}
		require.NoError(t, w.WriteMsg(&utxo))
	}
	return buf.Bytes()
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, data, 0o644))
}

// writeChunks writes each record set as one chunk file and returns the hashes.
func writeChunks(t *testing.T, ul UtxoLoader, recordSets ...[]byte) [][]byte {
	t.Helper()
	var hashes [][]byte
	for i, records := range recordSets {
		h, err := types.UtxoChunkHashes(bytes.NewReader(records))
		require.NoError(t, err)
		require.Len(t, h, 1)
		writeFile(t, ul.chunkFile(uint64(i)), records)
		hashes = append(hashes, h[0])
	}
	return hashes
}

func setChunkHashes(t *testing.T, ctx sdk.Context, k *keeper.Keeper, hashes [][]byte) {
	t.Helper()
	for i, h := range hashes {
		require.NoError(t, k.UtxoChunkHashes.Set(ctx, uint64(i), h))
	}
}

func TestPrepareUtxoChunks(t *testing.T) {
	ctx, _ := newLoaderTestKeeper(t)
	file := utxoRecords(t, 1, 5)
	hashes, err := types.UtxoChunkHashes(bytes.NewReader(file))
	require.NoError(t, err)

	t.Run("splits genesis.bin and keeps it", func(t *testing.T) {
		ul := NewUtxoLoader(t.TempDir())
		writeFile(t, ul.genesisFile(), file)
		require.NoError(t, ul.PrepareUtxoChunks(ctx, hashes))
		chunk, err := os.ReadFile(ul.chunkFile(0))
		require.NoError(t, err)
		require.Equal(t, file, chunk)
		require.FileExists(t, ul.genesisFile())
		require.NoFileExists(t, ul.chunkFile(0)+".tmp")

		// A replayed InitChain finds matching chunk files and does not need genesis.bin.
		require.NoError(t, os.Remove(ul.genesisFile()))
		require.NoError(t, ul.PrepareUtxoChunks(ctx, hashes))
	})
	t.Run("hash mismatch", func(t *testing.T) {
		ul := NewUtxoLoader(t.TempDir())
		writeFile(t, ul.genesisFile(), utxoRecords(t, 1, 4))
		require.ErrorContains(t, ul.PrepareUtxoChunks(ctx, hashes), "genesis expects")
	})
	t.Run("chunk count mismatch", func(t *testing.T) {
		ul := NewUtxoLoader(t.TempDir())
		writeFile(t, ul.genesisFile(), file)
		require.ErrorContains(t, ul.PrepareUtxoChunks(ctx, append(hashes, hashes[0])), "splits into 1 chunks")
	})
	t.Run("hashes without genesis.bin", func(t *testing.T) {
		ul := NewUtxoLoader(t.TempDir())
		require.ErrorIs(t, ul.PrepareUtxoChunks(ctx, hashes), os.ErrNotExist)
	})
	t.Run("genesis.bin without hashes", func(t *testing.T) {
		ul := NewUtxoLoader(t.TempDir())
		writeFile(t, ul.genesisFile(), file)
		require.ErrorContains(t, ul.PrepareUtxoChunks(ctx, nil), "no utxo_chunk_hashes")
	})
	t.Run("no snapshot", func(t *testing.T) {
		ul := NewUtxoLoader(t.TempDir())
		require.NoError(t, ul.PrepareUtxoChunks(ctx, nil))
	})
}

func TestLoadNextUtxoChunk(t *testing.T) {
	ctx, k := newLoaderTestKeeper(t)
	ul := NewUtxoLoader(t.TempDir())
	hashes := writeChunks(t, ul, utxoRecords(t, 1, 3), utxoRecords(t, 4, 2))
	setChunkHashes(t, ctx, k, hashes)

	loaded, err := k.UtxoSnapshotLoaded(ctx)
	require.NoError(t, err)
	require.False(t, loaded)

	require.NoError(t, ul.LoadNextUtxoChunk(ctx, k))
	_, err = k.Utxoes.Get(ctx, fmt.Sprintf("%064x-0", 3))
	require.NoError(t, err, "chunk 0 is in state")
	_, err = k.Utxoes.Get(ctx, fmt.Sprintf("%064x-0", 4))
	require.Error(t, err, "chunk 1 is not yet")
	loaded, err = k.UtxoSnapshotLoaded(ctx)
	require.NoError(t, err)
	require.False(t, loaded)

	require.NoError(t, ul.LoadNextUtxoChunk(ctx, k))
	_, err = k.Utxoes.Get(ctx, fmt.Sprintf("%064x-0", 5))
	require.NoError(t, err)
	loaded, err = k.UtxoSnapshotLoaded(ctx)
	require.NoError(t, err)
	require.True(t, loaded)

	// Nothing is left to load, and the chunk files stay on disk.
	require.NoError(t, ul.LoadNextUtxoChunk(ctx, k))
	require.FileExists(t, ul.chunkFile(0))
	require.FileExists(t, ul.chunkFile(1))

	// A block executed again starts from the committed progress and finds
	// its chunk file again.
	require.NoError(t, k.UtxoChunksLoaded.Set(ctx, 1))
	require.NoError(t, ul.LoadNextUtxoChunk(ctx, k))
	next, _, done, err := k.NextUtxoChunk(ctx)
	require.NoError(t, err)
	require.True(t, done)
	require.Equal(t, uint64(2), next)
}

func TestLoadNextUtxoChunk_Failures(t *testing.T) {
	t.Run("missing chunk file", func(t *testing.T) {
		ctx, k := newLoaderTestKeeper(t)
		ul := NewUtxoLoader(t.TempDir())
		hashes := writeChunks(t, ul, utxoRecords(t, 1, 2))
		setChunkHashes(t, ctx, k, hashes)
		require.NoError(t, os.Remove(ul.chunkFile(0)))
		require.ErrorIs(t, ul.LoadNextUtxoChunk(ctx, k), os.ErrNotExist)
		next, _, _, err := k.NextUtxoChunk(ctx)
		require.NoError(t, err)
		require.Equal(t, uint64(0), next)
	})
	t.Run("altered chunk file", func(t *testing.T) {
		ctx, k := newLoaderTestKeeper(t)
		ul := NewUtxoLoader(t.TempDir())
		hashes := writeChunks(t, ul, utxoRecords(t, 1, 2))
		setChunkHashes(t, ctx, k, hashes)
		writeFile(t, ul.chunkFile(0), utxoRecords(t, 7, 2))
		require.ErrorContains(t, ul.LoadNextUtxoChunk(ctx, k), "genesis expects")
		next, _, _, err := k.NextUtxoChunk(ctx)
		require.NoError(t, err)
		require.Equal(t, uint64(0), next, "a failed chunk is not marked loaded")
	})
	t.Run("truncated chunk file", func(t *testing.T) {
		ctx, k := newLoaderTestKeeper(t)
		ul := NewUtxoLoader(t.TempDir())
		records := utxoRecords(t, 1, 2)
		hashes := writeChunks(t, ul, records)
		setChunkHashes(t, ctx, k, hashes)
		writeFile(t, ul.chunkFile(0), records[:len(records)-4])
		require.Error(t, ul.LoadNextUtxoChunk(ctx, k))
	})
}

func TestLoadNextUtxoChunk_GenesisCoinbaseIsClaimed(t *testing.T) {
	ctx, k := newLoaderTestKeeper(t)
	ul := NewUtxoLoader(t.TempDir())
	var buf bytes.Buffer
	w := protoio.NewDelimitedWriter(&buf)
	require.NoError(t, w.WriteMsg(&types.UTXO{Txid: genesisCoinbaseTxid, Amount: 5_000_000_000, EntitledAmount: 5_000_000_000}))
	setChunkHashes(t, ctx, k, writeChunks(t, ul, buf.Bytes()))

	require.NoError(t, ul.LoadNextUtxoChunk(ctx, k))
	utxo, err := k.Utxoes.Get(ctx, genesisCoinbaseTxid+"-0")
	require.NoError(t, err)
	require.Equal(t, uint64(0), utxo.EntitledAmount)
}
