package keeper

import "github.com/btcsuite/btcd/chaincfg"

// SetBtcParamsForTesting makes the keeper verify reported blocks against
// params instead of mainnet, so tests can mine regtest blocks.
func (k *Keeper) SetBtcParamsForTesting(params *chaincfg.Params) {
	k.btcParams = params
}
