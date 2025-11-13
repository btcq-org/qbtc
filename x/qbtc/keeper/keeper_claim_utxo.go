package keeper

import (
	"context"
	"fmt"

	"cosmossdk.io/math"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (k Keeper) ClaimUTXO(ctx context.Context, txid string, vout uint32) error {
	key := getUTXOKey(txid, vout)
	utxo, err := k.Utxoes.Get(ctx, key)
	if err != nil {
		return err
	}
	if utxo.EntitledAmount == 0 {
		return fmt.Errorf("UTXO not entitled to claim")
	}

	// mint the coins to the module account
	if err := k.bankKeeper.MintCoins(ctx, types.ReserveModuleName, sdk.NewCoins(sdk.NewCoin(sdk.DefaultBondDenom, math.NewInt(int64(utxo.EntitledAmount))))); err != nil {
		return err
	}

	// reset the entitled amount to 0
	utxo.EntitledAmount = 0
	if err := k.Utxoes.Set(ctx, key, utxo); err != nil {
		return err
	}
	return nil
}
