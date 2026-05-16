package keeper

import (
	"context"

	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerror "github.com/cosmos/cosmos-sdk/types/errors"
)

// ClaimUTXO claims a UTXO.
// It mints the coins to the recipient (or reserve module account if recipient is nil) and resets the entitled amount to 0.
func (k Keeper) ClaimUTXO(ctx context.Context, txid []byte, vout uint32, recipient sdk.AccAddress) error {
	if len(txid) != types.BitcoinTxIDLength {
		return sdkerror.ErrInvalidRequest.Wrapf("txid must be %d bytes, got %d", types.BitcoinTxIDLength, len(txid))
	}
	key := types.UTXOKey(txid, vout)
	utxo, err := k.Utxoes.Get(ctx, key)
	if err != nil {
		return err
	}
	if utxo.EntitledAmount == 0 {
		return nil
	}

	coin := sdk.NewInt64Coin(sdk.DefaultBondDenom, int64(utxo.EntitledAmount))
	coins := sdk.NewCoins(coin)

	if recipient == nil {
		if err := k.bankKeeper.MintCoins(ctx, types.ReserveModuleName, coins); err != nil {
			return err
		}
	} else {
		if err := k.bankKeeper.MintCoins(ctx, types.ModuleName, coins); err != nil {
			return err
		}
		if err := k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, recipient, coins); err != nil {
			return err
		}
	}

	utxo.EntitledAmount = 0
	if err := k.Utxoes.Set(ctx, key, utxo); err != nil {
		return err
	}
	return nil
}
