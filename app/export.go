package app

import (
	"encoding/json"
	"errors"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"

	servertypes "github.com/cosmos/cosmos-sdk/server/types"
)

// ExportAppStateAndValidators exports the state of the application for a genesis
// file.
//
// A zero-height export must also reset distribution, staking and slashing
// heights, as simapp's prepForZeroHeightGenesis does. qbtc does not implement
// that for SDK v0.55, so it refuses the export instead of writing a genesis
// with inconsistent state.
func (app *App) ExportAppStateAndValidators(forZeroHeight bool, _, modulesToExport []string) (servertypes.ExportedApp, error) {
	if forZeroHeight {
		return servertypes.ExportedApp{}, errors.New("export --for-zero-height is not supported; export at the last height instead")
	}

	ctx := app.NewContextLegacy(true, cmtproto.Header{Height: app.LastBlockHeight()})

	// We export at last height + 1, because that's the height at which
	// CometBFT will start InitChain.
	height := app.LastBlockHeight() + 1

	genState, err := app.ModuleManager.ExportGenesisForModules(ctx, app.appCodec, modulesToExport)
	if err != nil {
		return servertypes.ExportedApp{}, err
	}

	appState, err := json.MarshalIndent(genState, "", "  ")
	if err != nil {
		return servertypes.ExportedApp{}, err
	}

	return servertypes.ExportedApp{
		AppState:        appState,
		Height:          height,
		ConsensusParams: app.GetConsensusParams(ctx),
	}, err
}
