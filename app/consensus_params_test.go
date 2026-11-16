package app

import (
	"math"
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/mempool"
	"github.com/stretchr/testify/require"

	"github.com/btcq-org/qbtc/constants"
	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// CometBFT's mempool admits a transaction only if the gas it reports fits
// block.max_gas. A free claim reports its gas meter's limit.
func TestFreeClaimGasFitsBlockMaxGas(t *testing.T) {
	postCheck := mempool.PostCheckMaxGas(DefaultBlockMaxGas)
	for n := 1; n <= types.MaxBatchClaimUTXOs; n++ {
		res := &abci.ResponseCheckTx{GasWanted: int64(types.FreeClaimGasLimit(n))}
		require.NoError(t, postCheck(nil, res), "claim of %d UTXOs", n)
	}

	// An infinite gas meter's limit reports -1, which CometBFT drops once
	// max_gas is set.
	var infinite uint64 = math.MaxUint64
	require.Error(t, postCheck(nil, &abci.ResponseCheckTx{GasWanted: int64(infinite)}))

	// A block of MaxClaimsPerBlock one-UTXO claims fits max_gas.
	maxClaims := uint64(constants.DefaultValues[constants.MaxClaimsPerBlock])
	require.LessOrEqual(t, maxClaims*types.FreeClaimBaseGas, uint64(DefaultBlockMaxGas))
}
