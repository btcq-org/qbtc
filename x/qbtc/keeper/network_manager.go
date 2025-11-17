package keeper

import (
	"context"

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
	emissionCurve := nm.k.GetConfig(sdkCtx, constants.EmissionCurve)
	blocksPerYear := nm.k.GetConfig(sdkCtx, constants.BlocksPerYear)
	systemIncome := qbtcReserveCoin.Amount.Quo(math.NewInt(emissionCurve)).Quo(math.NewInt(blocksPerYear))

	// TODO: double check , send income to fee collector, will staking module auto distribute to stakers?
	return nm.k.bankKeeper.SendCoinsFromModuleToModule(sdkCtx, types.ReserveModuleName, authtypes.FeeCollectorName,
		sdk.NewCoins(
			sdk.NewCoin(sdk.DefaultBondDenom, systemIncome)))
}
