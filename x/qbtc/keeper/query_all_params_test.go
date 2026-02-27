package keeper_test

import (
	"sort"
	"testing"

	"github.com/btcq-org/qbtc/constants"
	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/assert"
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

// TestAllParamsReturnsDefaultsWithNoOverrides verifies that when no overrides
// are set, AllParams returns exactly the default values from
// constants.DefaultValues — not zero values.
func TestAllParamsReturnsDefaultsWithNoOverrides(t *testing.T) {
	f := initFixture(t)
	queryClient := keeper.NewQueryServerImpl(f.keeper)

	resp, err := queryClient.AllParams(f.ctx, &types.QueryAllParamsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Params, len(constants.DefaultValues),
		"should return one param per constant")

	returned := make(map[string]int64, len(resp.Params))
	for _, p := range resp.Params {
		returned[p.Key] = p.Value
	}

	for name, expected := range constants.DefaultValues {
		actual, ok := returned[name.String()]
		assert.True(t, ok, "missing param %q", name.String())
		assert.Equal(t, expected, actual,
			"param %q should be the default value, not zero", name.String())
	}
}

// TestAllParamsPreservesDefaultOnCorruptOverride verifies that when a
// ConstOverrides entry is corrupt (causing a decode error, not ErrNotFound),
// AllParams still returns the original default value rather than silently
// zeroing it out.
func TestAllParamsPreservesDefaultOnCorruptOverride(t *testing.T) {
	f := initFixture(t)
	sdkCtx := sdk.UnwrapSDKContext(f.ctx)
	queryClient := keeper.NewQueryServerImpl(f.keeper)

	// Pick a param with a non-zero default so we can detect zeroing.
	targetKey := constants.EmissionCurve
	expectedDefault := constants.DefaultValues[targetKey]
	require.NotZero(t, expectedDefault, "need a non-zero default to detect the bug")

	keyStr := targetKey.String()

	// Write a valid override first so the collections.Map creates the
	// correctly-encoded store key for us.
	require.NoError(t, f.keeper.ConstOverrides.Set(sdkCtx, keyStr, 999))

	// Sanity: the valid override is readable.
	val, err := f.keeper.ConstOverrides.Get(sdkCtx, keyStr)
	require.NoError(t, err)
	require.Equal(t, int64(999), val)

	// Now overwrite the same store entry with garbage bytes.  We find the
	// exact encoded key by iterating the raw store under the known prefix.
	rawStore := sdkCtx.KVStore(f.storeKey)
	prefix := []byte("const_override")
	end := make([]byte, len(prefix))
	copy(end, prefix)
	end[len(end)-1]++
	iter := rawStore.Iterator(prefix, end)
	defer iter.Close()
	var corruptedKey []byte
	for ; iter.Valid(); iter.Next() {
		corruptedKey = iter.Key()
		break // only need the first (and only) entry
	}
	require.NotNil(t, corruptedKey, "should have found the encoded key in the store")
	rawStore.Set(corruptedKey, []byte("garbage"))

	// Verify Get now fails with a non-ErrNotFound decode error.
	_, err = f.keeper.ConstOverrides.Get(sdkCtx, keyStr)
	require.Error(t, err, "Get should fail on corrupt data")

	// Now call AllParams — the corrupt key should NOT zero out the value
	resp, err := queryClient.AllParams(f.ctx, &types.QueryAllParamsRequest{})
	require.NoError(t, err)

	for _, p := range resp.Params {
		if p.Key == keyStr {
			assert.Equal(t, expectedDefault, p.Value,
				"param %q must retain its default (%d) when the override is corrupt, got %d (zeroed)",
				keyStr, expectedDefault, p.Value)
			return
		}
	}
	t.Fatalf("param %q not found in AllParams response", keyStr)
}
