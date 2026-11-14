package cmd

import (
	"context"
	"errors"
	"fmt"

	cmtmldsa65 "github.com/cometbft/cometbft/crypto/mldsa65"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"

	"cosmossdk.io/log/v2"
	confixcmd "cosmossdk.io/tools/confix/cmd"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/debug"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/keys"
	"github.com/cosmos/cosmos-sdk/client/pruning"
	"github.com/cosmos/cosmos-sdk/client/rpc"
	"github.com/cosmos/cosmos-sdk/client/snapshot"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/server"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	authcmd "github.com/cosmos/cosmos-sdk/x/auth/client/cli"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/cosmos/cosmos-sdk/x/genutil"
	genutilcli "github.com/cosmos/cosmos-sdk/x/genutil/client/cli"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"

	"github.com/btcq-org/qbtc/app"
)

func initRootCmd(
	rootCmd *cobra.Command,
	txConfig client.TxConfig,
	basicManager module.BasicManager,
) {
	initCmd := genutilcli.InitCmd(basicManager, app.DefaultNodeHome)
	setFlagDefault(initCmd, genutilcli.FlagConsensusKeyAlgo, cmtmldsa65.KeyType)
	initCmd.PostRunE = setGenesisBlockGasLimit

	rootCmd.AddCommand(
		initCmd,
		NewInPlaceTestnetCmd(),
		NewTestnetMultiNodeCmd(basicManager, banktypes.GenesisBalancesIterator{}),
		debug.Cmd(),
		confixcmd.ConfigCommand(),
		pruning.Cmd(newApp, app.DefaultNodeHome),
		snapshot.Cmd(newApp),
	)

	// the app built by qbtcd start, for PostSetup
	var startedApp *app.App
	startAppCreator := func(logger log.Logger, db dbm.DB, appOpts servertypes.AppOptions) servertypes.Application {
		a := newApp(logger, db, appOpts)
		startedApp, _ = a.(*app.App)
		return a
	}
	server.AddCommandsWithStartCmdOptions(rootCmd, app.DefaultNodeHome, startAppCreator, appExport, server.StartCmdOptions{
		AddFlags: addModuleInitFlags,
		// RegisterNodeService only starts the Bitcoin reader when the API or
		// gRPC server is enabled; a validator needs it either way.
		PostSetup: func(_ *server.Context, _ client.Context, _ context.Context, _ *errgroup.Group) error {
			if startedApp == nil {
				return errors.New("qbtcd start did not build the qbtc app")
			}
			return startedApp.StartBitcoinReader()
		},
	})

	genesisCmd := genutilcli.Commands(txConfig, basicManager, app.DefaultNodeHome)
	genesisCmd.AddCommand(NewSetUtxoChunkHashesCmd(app.DefaultNodeHome))

	// add keybase, auxiliary RPC, query, genesis, and tx child commands
	rootCmd.AddCommand(
		server.StatusCommand(),
		genesisCmd,
		queryCommand(),
		txCommand(),
		keysCommands(),
	)
}

// keysCommands returns the keys commands with `keys add` defaulting to the
// chain's only account key type; the keyring itself refuses other algorithms.
func keysCommands() *cobra.Command {
	cmd := keys.Commands()
	for _, sub := range cmd.Commands() {
		if sub.Name() == "add" {
			setFlagDefault(sub, flags.FlagKeyType, string(hd.MlDsa65Type))
		}
	}
	return cmd
}

// setGenesisBlockGasLimit runs after `qbtcd init` and sets block.max_gas in
// the genesis file init wrote.
func setGenesisBlockGasLimit(cmd *cobra.Command, _ []string) error {
	genFile := server.GetServerContextFromCmd(cmd).Config.GenesisFile()
	appGenesis, err := genutiltypes.AppGenesisFromFile(genFile)
	if err != nil {
		return err
	}
	if err := applyQbtcBlockGasLimit(appGenesis); err != nil {
		return err
	}
	return genutil.ExportGenesisFile(appGenesis, genFile)
}

// setFlagDefault changes the default of an already defined flag.
func setFlagDefault(cmd *cobra.Command, name, value string) {
	f := cmd.Flags().Lookup(name)
	if f == nil {
		panic(fmt.Sprintf("command %s has no flag %s", cmd.Name(), name))
	}
	f.DefValue = value
	if err := f.Value.Set(value); err != nil {
		panic(err)
	}
}

// addModuleInitFlags adds more flags to the start command.
func addModuleInitFlags(startCmd *cobra.Command) {
}

func queryCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        "query",
		Aliases:                    []string{"q"},
		Short:                      "Querying subcommands",
		DisableFlagParsing:         false,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	cmd.AddCommand(
		rpc.WaitTxCmd(),
		rpc.ValidatorCommand(),
		server.QueryBlockCmd(),
		authcmd.QueryTxsByEventsCmd(),
		server.QueryBlocksCmd(),
		authcmd.QueryTxCmd(),
		server.QueryBlockResultsCmd(),
	)

	return cmd
}

func txCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        "tx",
		Short:                      "Transactions subcommands",
		DisableFlagParsing:         false,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	cmd.AddCommand(
		authcmd.GetSignCommand(),
		authcmd.GetSignBatchCommand(),
		authcmd.GetMultiSignCommand(),
		authcmd.GetMultiSignBatchCmd(),
		authcmd.GetValidateSignaturesCommand(),
		flags.LineBreak,
		authcmd.GetBroadcastCommand(),
		authcmd.GetEncodeCommand(),
		authcmd.GetDecodeCommand(),
		authcmd.GetSimulateCmd(),
	)

	return cmd
}

// newApp creates the application
func newApp(
	logger log.Logger,
	db dbm.DB,
	appOpts servertypes.AppOptions,
) servertypes.Application {
	baseappOptions := server.DefaultBaseappOptions(appOpts)

	return app.New(
		logger, db, true,
		appOpts,
		baseappOptions...,
	)
}

// appExport creates a new app (optionally at a given height) and exports state.
func appExport(
	logger log.Logger,
	db dbm.DB,
	height int64,
	forZeroHeight bool,
	jailAllowedAddrs []string,
	appOpts servertypes.AppOptions,
	modulesToExport []string,
) (servertypes.ExportedApp, error) {
	var bApp *app.App

	// this check is necessary as we use the flag in x/upgrade.
	// we can exit more gracefully by checking the flag here.
	homePath, ok := appOpts.Get(flags.FlagHome).(string)
	if !ok || homePath == "" {
		return servertypes.ExportedApp{}, errors.New("application home not set")
	}

	viperAppOpts, ok := appOpts.(*viper.Viper)
	if !ok {
		return servertypes.ExportedApp{}, errors.New("appOpts is not viper.Viper")
	}

	appOpts = viperAppOpts
	if height != -1 {
		bApp = app.New(logger, db, false, appOpts)
		if err := bApp.LoadHeight(height); err != nil {
			return servertypes.ExportedApp{}, err
		}
	} else {
		bApp = app.New(logger, db, true, appOpts)
	}

	return bApp.ExportAppStateAndValidators(forZeroHeight, jailAllowedAddrs, modulesToExport)
}
