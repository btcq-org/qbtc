package keeper_test

import (
	"testing"

	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/stretchr/testify/require"
)

func TestQueryLastProcessedBlock(t *testing.T) {
	f := initFixture(t)
	queryClient := keeper.NewQueryServerImpl(f.keeper)

	f.keeper.LastProcessedBlock.Set(f.ctx, 100)
	height, err := queryClient.LastProcessedBlock(f.ctx, &types.QueryLastProcessedBlockRequest{})
	require.NoError(t, err)
	require.NotNil(t, height)
	require.Equal(t, uint64(100), height.Height)
}
