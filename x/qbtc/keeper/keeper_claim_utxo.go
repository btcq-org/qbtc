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

// GovClaimUTXO claims a UTXO on behalf of governance, splitting the entitled amount:
// 5% to devAddr (if set), 5% to mktAddr (if set), remainder to the reserve module account.
// Returns (devAmount, mktAmount, reserveAmount, error).
func (k Keeper) GovClaimUTXO(ctx context.Context, txid string, vout uint32, devAddr sdk.AccAddress, mktAddr sdk.AccAddress) (uint64, uint64, uint64, error) {
	key := getUTXOKey(txid, vout)
	utxo, err := k.Utxoes.Get(ctx, key)
	if err != nil {
		return 0, 0, 0, err
	}
	if utxo.EntitledAmount == 0 {
		return 0, 0, 0, nil
	}

	total := utxo.EntitledAmount
	var devAmount, mktAmount uint64
	if len(devAddr) > 0 {
		devAmount = total * 5 / 100
	}
	if len(mktAddr) > 0 {
		mktAmount = total * 5 / 100
	}
	reserveAmount := total - devAmount - mktAmount

	// Mint the full amount to the qbtc module, then distribute.
	totalCoins := sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, int64(total)))
	if err := k.bankKeeper.MintCoins(ctx, types.ModuleName, totalCoins); err != nil {
		return 0, 0, 0, err
	}
	if devAmount > 0 {
		devCoins := sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, int64(devAmount)))
		if err := k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, devAddr, devCoins); err != nil {
			return 0, 0, 0, err
		}
	}
	if mktAmount > 0 {
		mktCoins := sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, int64(mktAmount)))
		if err := k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, mktAddr, mktCoins); err != nil {
			return 0, 0, 0, err
		}
	}
	if reserveAmount > 0 {
		reserveCoins := sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, int64(reserveAmount)))
		if err := k.bankKeeper.SendCoinsFromModuleToModule(ctx, types.ModuleName, types.ReserveModuleName, reserveCoins); err != nil {
			return 0, 0, 0, err
		}
	}

	utxo.EntitledAmount = 0
	if err := k.Utxoes.Set(ctx, key, utxo); err != nil {
		return 0, 0, 0, err
	}
	return devAmount, mktAmount, reserveAmount, nil
}
