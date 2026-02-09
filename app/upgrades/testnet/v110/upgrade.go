package v110

import (
	"context"
	"time"

	storetypes "cosmossdk.io/store/types"
	upgradetypes "cosmossdk.io/x/upgrade/types"
	"github.com/btcq-org/qbtc/app/upgrades"
	"github.com/cosmos/cosmos-sdk/types/module"
	tokenfactorytypes "github.com/cosmos/tokenfactory/x/tokenfactory/types"

	errorsmod "cosmossdk.io/errors"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

const UpgradeName = "v110"

var Upgrade = upgrades.Upgrade{
	UpgradeName: UpgradeName,
	StoreUpgrades: storetypes.StoreUpgrades{
		Added: []string{
			tokenfactorytypes.ModuleName,
		},
	},
	CreateUpgradeHandler: func(mm *module.Manager, configurator module.Configurator) upgradetypes.UpgradeHandler {
		return func(c context.Context, _ upgradetypes.Plan, fromVM module.VersionMap) (module.VersionMap, error) {
			ctx := sdk.UnwrapSDKContext(c)
			ctx.Logger().Info("migration started")
			startTime := time.Now()
			vm, err := mm.RunMigrations(ctx, configurator, fromVM)
			if err != nil {
				return vm, errorsmod.Wrapf(err, "running module migrations")
			}
			ctx.Logger().Info("upgrade completed", "elapsed", time.Since(startTime).Milliseconds())
			return vm, nil
		}
	},
}
