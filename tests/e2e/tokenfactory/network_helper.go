package tokenfactory

import (
	"encoding/json"

	dbm "github.com/cosmos/cosmos-db"

	"cosmossdk.io/log"
	pruningtypes "cosmossdk.io/store/pruning/types"

	"github.com/btcq-org/qbtc/app"
	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/client/flags"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	"github.com/cosmos/cosmos-sdk/testutil/network"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	moduletestutil "github.com/cosmos/cosmos-sdk/types/module/testutil"
)

// newAppOptions returns AppOptions with the home directory set and ebifrost
// disabled since it is not needed for integration tests.
func newAppOptions(home string) simtestutil.AppOptionsMap {
	return simtestutil.AppOptionsMap{
		flags.FlagHome:    home,
		"ebifrost.enable": false,
	}
}

// NewTestNetworkFixture returns a TestFixture that bootstraps a full qbtc App
// (including IBC, WASM, and tokenfactory) for use with the SDK test network.
// tmpDir is used as the home directory for a throwaway app instance that
// extracts codecs and default genesis; pass t.TempDir() so nothing is left
// behind in the working directory.
func NewTestNetworkFixture(tmpDir string) network.TestFixture {
	// Build a temporary app instance just to extract codecs and default genesis.
	tmpApp := app.New(
		log.NewNopLogger(),
		dbm.NewMemDB(),
		nil,   // traceStore
		true,  // loadLatest
		newAppOptions(tmpDir),
	)

	return network.TestFixture{
		AppConstructor: func(val network.ValidatorI) servertypes.Application {
			return app.New(
				val.GetCtx().Logger,
				dbm.NewMemDB(),
				nil,   // traceStore
				true,  // loadLatest
				newAppOptions(val.GetCtx().Config.RootDir),
				baseapp.SetPruning(pruningtypes.NewPruningOptionsFromString(val.GetAppConfig().Pruning)),
				baseapp.SetMinGasPrices(val.GetAppConfig().MinGasPrices),
				baseapp.SetChainID(val.GetCtx().Viper.GetString("chain-id")),
			)
		},
		GenesisState: func() map[string]json.RawMessage {
			return tmpApp.DefaultGenesis()
		}(),
		EncodingConfig: moduletestutil.TestEncodingConfig{
			InterfaceRegistry: tmpApp.InterfaceRegistry(),
			Codec:             tmpApp.AppCodec(),
			TxConfig:          tmpApp.TxConfig(),
			Amino:             tmpApp.LegacyAmino(),
		},
	}
}
