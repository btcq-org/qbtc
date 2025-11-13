package keeper

import (
	"context"

	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// ClaimUTXO claims a UTXO by the governance module.
// It mints the coins to the reserve module account and resets the entitled amount to 0.
func (k Keeper) ClaimUTXO(ctx context.Context, txid string, vout uint32) error {
	key := getUTXOKey(txid, vout)
	utxo, err := k.Utxoes.Get(ctx, key)
	if err != nil {
		return err
	}
	if utxo.EntitledAmount == 0 {
		return nil
	}

	// denom is set in app/config.go
	coin := sdk.NewInt64Coin(sdk.DefaultBondDenom, int64(utxo.EntitledAmount))
	// mint the coins to the module account
	if err := k.bankKeeper.MintCoins(ctx, types.ReserveModuleName, sdk.NewCoins(coin)); err != nil {
		return err
	}

	// reset the entitled amount to 0
	utxo.EntitledAmount = 0
	if err := k.Utxoes.Set(ctx, key, utxo); err != nil {
		return err
	}
	return nil
}
