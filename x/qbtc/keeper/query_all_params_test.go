package keeper_test

import (
	"sort"
	"testing"

	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/stretchr/testify/require"
)

// TestAllParamsReturnsDeterministicOrder calls AllParams multiple times and
// verifies the result keys are always sorted lexicographically.
func TestAllParamsReturnsDeterministicOrder(t *testing.T) {
	f := initFixture(t)
	queryClient := keeper.NewQueryServerImpl(f.keeper)

	// Call AllParams enough times to expose non-determinism with high
	// probability.  With 3 map entries, the chance that 50 consecutive
	// iterations all happen to come out sorted is (1/3!)^50 ≈ 0.
	for i := 0; i < 50; i++ {
		resp, err := queryClient.AllParams(f.ctx, &types.QueryAllParamsRequest{})
		require.NoError(t, err)
		require.NotEmpty(t, resp.Params)

		keys := make([]string, len(resp.Params))
		for j, p := range resp.Params {
			keys[j] = p.Key
		}

		require.True(t, sort.StringsAreSorted(keys),
			"iteration %d: AllParams keys must be sorted, got %v", i, keys)
	}
}
