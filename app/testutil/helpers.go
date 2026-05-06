package apptestutil

import (
	"fmt"
	"os"

	dbm "github.com/cosmos/cosmos-db"

	"cosmossdk.io/log"
	pruningtypes "cosmossdk.io/store/pruning/types"

	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/client/flags"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	"github.com/cosmos/cosmos-sdk/testutil/network"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	moduletestutil "github.com/cosmos/cosmos-sdk/types/module/testutil"

	"github.com/btcq-org/qbtc/app"
)

// NewTestNetworkFixture returns a TestFixture for cosmos-sdk's testutil/network
// harness. It mirrors simapp.NewTestNetworkFixture: a throwaway app instance is
// built solely to extract codecs and default genesis; per-validator apps are
// constructed later against each validator's own RootDir. Callers typically
// customize cfg.GenesisState for their module after DefaultConfig returns.
//
// ebifrost is disabled — integration tests do not use P2P gossip and enabling
// it would spawn a libp2p host per validator.
func NewTestNetworkFixture() network.TestFixture {
	dir, err := os.MkdirTemp("", "qbtc")
	if err != nil {
		panic(fmt.Sprintf("failed creating temporary directory: %v", err))
	}
	defer os.RemoveAll(dir)

	tmpApp := app.New(
		log.NewNopLogger(),
		dbm.NewMemDB(),
		nil,
		true,
		testAppOptions(dir),
	)

	return network.TestFixture{
		AppConstructor: func(val network.ValidatorI) servertypes.Application {
			return app.New(
				val.GetCtx().Logger,
				dbm.NewMemDB(),
				nil,
				true,
				testAppOptions(val.GetCtx().Config.RootDir),
				baseapp.SetPruning(pruningtypes.NewPruningOptionsFromString(val.GetAppConfig().Pruning)),
				baseapp.SetMinGasPrices(val.GetAppConfig().MinGasPrices),
				baseapp.SetChainID(val.GetCtx().Viper.GetString(flags.FlagChainID)),
			)
		},
		GenesisState: tmpApp.DefaultGenesis(),
		EncodingConfig: moduletestutil.TestEncodingConfig{
			InterfaceRegistry: tmpApp.InterfaceRegistry(),
			Codec:             tmpApp.AppCodec(),
			TxConfig:          tmpApp.TxConfig(),
			Amino:             tmpApp.LegacyAmino(),
		},
	}
}

func testAppOptions(home string) simtestutil.AppOptionsMap {
	return simtestutil.AppOptionsMap{
		flags.FlagHome:    home,
		"ebifrost.enable": false,
	}
}
