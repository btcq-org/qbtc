package keeper

import (
	"context"

	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// ClaimUTXO claims a UTXO.
// It mints the coins to the recipient (or reserve module account if recipient is nil) and resets the entitled amount to 0.
func (k Keeper) ClaimUTXO(ctx context.Context, txid string, vout uint32, recipient sdk.AccAddress) error {
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
	coins := sdk.NewCoins(coin)

	if recipient == nil {
		// mint the coins to the reserve module account
		if err := k.bankKeeper.MintCoins(ctx, types.ReserveModuleName, coins); err != nil {
			return err
		}
	} else {
		// mint the coins to the module account then send to recipient
		// Using qbtc module account for minting
		if err := k.bankKeeper.MintCoins(ctx, types.ModuleName, coins); err != nil {
			return err
		}
		if err := k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, recipient, coins); err != nil {
			return err
		}
	}

	// reset the entitled amount to 0
	utxo.EntitledAmount = 0
	if err := k.Utxoes.Set(ctx, key, utxo); err != nil {
		return err
	}
	return nil
}
