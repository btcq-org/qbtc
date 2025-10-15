package cmd

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"cosmossdk.io/log"
	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/libs/bytes"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/server"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	"github.com/spf13/cast"
	"github.com/spf13/cobra"

	"btcq/app"
)

var flagAccountsToFund = "accounts-to-fund"

type valArgs struct {
	newValAddr         bytes.HexBytes
	newOperatorAddress string
	newValPubKey       crypto.PubKey
	accountsToFund     []string
	upgradeToTrigger   string
	homeDir            string
}

func NewInPlaceTestnetCmd() *cobra.Command {
	cmd := server.InPlaceTestnetCreator(newTestnetApp)
	cmd.Short = "Updates chain's application and consensus state with provided validator info and starts the node"
	cmd.Long = `The test command modifies both application and consensus stores within a local mainnet node and starts the node,
with the aim of facilitating testing procedures. This command replaces existing validator data with updated information,
thereby removing the old validator set and introducing a new set suitable for local testing purposes. By altering the state extracted from the mainnet node,
it enables developers to configure their local environments to reflect mainnet conditions more accurately.`

	cmd.Example = fmt.Sprintf(`%sd in-place-testnet testing-1 cosmosvaloper1w7f3xx7e75p4l7qdym5msqem9rd4dyc4mq79dm --home $HOME/.%sd/validator1 --validator-privkey=6dq+/KHNvyiw2TToCgOpUpQKIzrLs69Rb8Az39xvmxPHNoPxY1Cil8FY+4DhT9YwD6s0tFABMlLcpaylzKKBOg== --accounts-to-fund="cosmos1f7twgcq4ypzg7y24wuywy06xmdet8pc4473tnq,cosmos1qvuhm5m644660nd8377d6l7yz9e9hhm9evmx3x"`, "btcq", "btcq")

	cmd.Flags().String(flagAccountsToFund, "", "Comma-separated list of account addresses that will be funded for testing purposes")
	return cmd
}

// newTestnetApp starts by running the normal newApp method. From there, the app interface returned is modified in order
// for a testnet to be created from the provided app.
func newTestnetApp(logger log.Logger, db dbm.DB, traceStore io.Writer, appOpts servertypes.AppOptions) servertypes.Application {
	// Create an app and type cast to an App
	newApp := newApp(logger, db, traceStore, appOpts)
	testApp, ok := newApp.(*app.App)
	if !ok {
		panic("app created from newApp is not of type App")
	}

	// Get command args
	args, err := getCommandArgs(appOpts)
	if err != nil {
		panic(err)
	}

	return initAppForTestnet(testApp, args)
}

func initAppForTestnet(app *app.App, _ valArgs) *app.App {

	// Fund local accounts
	//for _, accountStr := range args.accountsToFund {
	//	handleErr(app.BankKeeper.MintCoins(ctx, minttypes.ModuleName, defaultCoins))
	//
	//	account, err := app.AuthKeeper.AddressCodec().StringToBytes(accountStr)
	//	handleErr(err)
	//
	//	handleErr(app.BankKeeper.SendCoinsFromModuleToAccount(ctx, minttypes.ModuleName, account, defaultCoins))
	//}

	return app
}

// parse the input flags and returns valArgs
func getCommandArgs(appOpts servertypes.AppOptions) (valArgs, error) {
	args := valArgs{}

	newValAddr, ok := appOpts.Get(server.KeyNewValAddr).(bytes.HexBytes)
	if !ok {
		return args, errors.New("newValAddr is not of type bytes.HexBytes")
	}
	args.newValAddr = newValAddr
	newValPubKey, ok := appOpts.Get(server.KeyUserPubKey).(crypto.PubKey)
	if !ok {
		return args, errors.New("newValPubKey is not of type crypto.PubKey")
	}
	args.newValPubKey = newValPubKey
	newOperatorAddress, ok := appOpts.Get(server.KeyNewOpAddr).(string)
	if !ok {
		return args, errors.New("newOperatorAddress is not of type string")
	}
	args.newOperatorAddress = newOperatorAddress
	upgradeToTrigger, ok := appOpts.Get(server.KeyTriggerTestnetUpgrade).(string)
	if !ok {
		return args, errors.New("upgradeToTrigger is not of type string")
	}
	args.upgradeToTrigger = upgradeToTrigger

	// parsing  and set accounts to fund
	accountsString := cast.ToString(appOpts.Get(flagAccountsToFund))
	args.accountsToFund = append(args.accountsToFund, strings.Split(accountsString, ",")...)

	// home dir
	homeDir := cast.ToString(appOpts.Get(flags.FlagHome))
	if homeDir == "" {
		return args, errors.New("invalid home dir")
	}
	args.homeDir = homeDir

	return args, nil
}
