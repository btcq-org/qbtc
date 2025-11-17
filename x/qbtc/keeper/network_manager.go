package keeper

import (
	"context"
	"fmt"

	"cosmossdk.io/math"
	"github.com/btcq-org/qbtc/constants"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
)

type NetworkManager struct {
	k Keeper
}

// NewNetworkManager creates a new NetworkManager instance.
func NewNetworkManager(k Keeper) *NetworkManager {
	return &NetworkManager{k: k}
}

// ProcessNetworkReward processes network rewards.
func (nm *NetworkManager) ProcessNetworkReward(ctx context.Context) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	qbtcReserveCoin := nm.k.GetBalanceOfModule(ctx, types.ReserveModuleName, sdk.DefaultBondDenom)
	if qbtcReserveCoin.IsZero() {
		sdkCtx.Logger().Info("qbtc reserve module balance is zero, ignore network reward")
		return nil
	}
	emissionCurve := nm.k.GetConfig(sdkCtx, constants.EmissionCurve)
	blocksPerYear := nm.k.GetConfig(sdkCtx, constants.BlocksPerYear)
	if emissionCurve <= 0 || blocksPerYear <= 0 {
		sdkCtx.Logger().Error(fmt.Sprintf("emission curve is: %d, blocksPerYear: %d , ignore network reward", emissionCurve, blocksPerYear))
		return nil
	}
	systemIncome := qbtcReserveCoin.Amount.Quo(math.NewInt(emissionCurve)).Quo(math.NewInt(blocksPerYear))
	if systemIncome.IsZero() {
		sdkCtx.Logger().Info("system income is zero, ignore network reward")
		return nil
	}
	// Transfer reward from reserve module to fee collector
	// Collected fee will be distributed to stakers by the distribution module
	return nm.k.bankKeeper.SendCoinsFromModuleToModule(sdkCtx, types.ReserveModuleName, authtypes.FeeCollectorName,
		sdk.NewCoins(
			sdk.NewCoin(sdk.DefaultBondDenom, systemIncome)))
}
