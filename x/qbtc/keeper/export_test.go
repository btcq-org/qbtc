package keeper

import (
	"github.com/btcsuite/btcd/chaincfg"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// SetBtcParamsForTesting makes the keeper verify reported blocks against
// params instead of mainnet, so tests can mine regtest blocks.
func (k *Keeper) SetBtcParamsForTesting(params *chaincfg.Params) {
	k.btcParams = params
}

// ReferralRewardForTesting exposes referralReward.
var ReferralRewardForTesting = referralReward

// ApplyReferralForTesting exposes applyReferral.
func (k Keeper) ApplyReferralForTesting(ctx sdk.Context, referrer, referee sdk.AccAddress, amount uint64) {
	k.applyReferral(ctx, referrer, referee, amount)
}
