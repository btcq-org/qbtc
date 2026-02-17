package app

import (
	"fmt"

	upgradetypes "cosmossdk.io/x/upgrade/types"
	"github.com/btcq-org/qbtc/app/upgrades"
	testnetupgradev110 "github.com/btcq-org/qbtc/app/upgrades/testnet/v110"
	"github.com/cosmos/cosmos-sdk/types/module"
)

var Upgrades = []upgrades.Upgrade{
	// testnet upgrades
	testnetupgradev110.Upgrade,
}

// RegisterUpgradeHandlers handles upgrade registration
func (app App) RegisterUpgradeHandlers(configurator module.Configurator) {
	for _, u := range Upgrades {
		app.UpgradeKeeper.SetUpgradeHandler(
			u.UpgradeName,
			u.CreateUpgradeHandler(app.ModuleManager, configurator),
		)
	}

	upgradeInfo, err := app.UpgradeKeeper.ReadUpgradeInfoFromDisk()
	if err != nil {
		panic(fmt.Sprintf("failed to read upgrade info from disk %s", err))
	}

	if app.UpgradeKeeper.IsSkipHeight(upgradeInfo.Height) {
		return
	}

	for _, u := range Upgrades {
		u := u
		if upgradeInfo.Name == u.UpgradeName {
			app.SetStoreLoader(upgradetypes.UpgradeStoreLoader(upgradeInfo.Height, &u.StoreUpgrades))
		}
	}
}
