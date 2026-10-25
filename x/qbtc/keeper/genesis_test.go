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
