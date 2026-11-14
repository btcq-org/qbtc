package keeper_test

import (
	"bytes"
	"testing"

	"github.com/btcq-org/qbtc/x/qbtc/types"

	"github.com/stretchr/testify/require"
)

func TestGenesis(t *testing.T) {
	genesisState := types.GenesisState{}

	f := initFixture(t)
	err := f.keeper.InitGenesis(f.ctx, genesisState)
	require.NoError(t, err)
	got, err := f.keeper.ExportGenesis(f.ctx)
	require.NoError(t, err)
	require.NotNil(t, got)

}

// The chunk hashes are stored at InitGenesis. The export refuses while chunks
// are left to load, since those UTXOs are only in the chunk files, and leaves
// the hashes out once every chunk is loaded, since the UTXOs are then exported.
func TestGenesis_UtxoChunkHashes(t *testing.T) {
	hashes := [][]byte{bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)}
	f := initFixture(t)
	require.NoError(t, f.keeper.InitGenesis(f.ctx, types.GenesisState{UtxoChunkHashes: hashes}))

	index, hash, done, err := f.keeper.NextUtxoChunk(f.ctx)
	require.NoError(t, err)
	require.False(t, done)
	require.Equal(t, uint64(0), index)
	require.Equal(t, hashes[0], hash)

	_, err = f.keeper.ExportGenesis(f.ctx)
	require.ErrorContains(t, err, "snapshot is loading")

	require.NoError(t, f.keeper.MarkUtxoChunkLoaded(f.ctx, 0))
	require.NoError(t, f.keeper.MarkUtxoChunkLoaded(f.ctx, 1))
	loaded, err := f.keeper.UtxoSnapshotLoaded(f.ctx)
	require.NoError(t, err)
	require.True(t, loaded)
	exported, err := f.keeper.ExportGenesis(f.ctx)
	require.NoError(t, err)
	require.Empty(t, exported.UtxoChunkHashes)
}

// The Bitcoin anchor is loaded from genesis, and an export carries the current
// tip forward as the anchor, so an imported chain continues at the next block.
func TestGenesis_BtcAnchor(t *testing.T) {
	f := initFixture(t)
	c := newRegtestChain(t, f, 800000)
	var anchor bytes.Buffer
	require.NoError(t, c.tip.Serialize(&anchor))
	genesisState := types.GenesisState{
		BtcInitialHeight:         800001,
		BtcAnchorHeader:          anchor.Bytes(),
		BtcAnchorPeriodStartTime: uint32(c.tip.Timestamp.Unix()),
	}

	imported := initFixture(t)
	require.NoError(t, imported.keeper.InitGenesis(imported.ctx, genesisState))
	exported, err := imported.keeper.ExportGenesis(imported.ctx)
	require.NoError(t, err)
	require.Equal(t, genesisState.BtcInitialHeight, exported.BtcInitialHeight)
	require.Equal(t, genesisState.BtcAnchorHeader, exported.BtcAnchorHeader)
	require.Equal(t, genesisState.BtcAnchorPeriodStartTime, exported.BtcAnchorPeriodStartTime)

	// after one more block, the export anchors at that block
	block := c.nextBlock(c.coinbase())
	c.mustSubmit(block)
	exported, err = f.keeper.ExportGenesis(f.ctx)
	require.NoError(t, err)
	var tip bytes.Buffer
	require.NoError(t, block.Header.Serialize(&tip))
	require.Equal(t, uint64(800002), exported.BtcInitialHeight)
	require.Equal(t, tip.Bytes(), exported.BtcAnchorHeader)
}
