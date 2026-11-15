package cmd

import (
	"os"
	"path/filepath"
	"testing"

	cmtmldsa65 "github.com/cometbft/cometbft/crypto/mldsa65"
	cmttypes "github.com/cometbft/cometbft/types"
	svrcmd "github.com/cosmos/cosmos-sdk/server/cmd"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	"github.com/stretchr/testify/require"

	"github.com/btcq-org/qbtc/app"
)

func TestApplyQbtcConsensusParams(t *testing.T) {
	appGenesis := genutiltypes.NewAppGenesisWithVersion("qbtc-test-1", nil)
	appGenesis.Consensus = &genutiltypes.ConsensusGenesis{Params: cmttypes.DefaultConsensusParams()}

	require.NoError(t, applyQbtcConsensusParams(appGenesis, initArgs{voteExtensionsEnableHeight: 2}))

	require.Equal(t, int64(2), appGenesis.Consensus.Params.ABCI.VoteExtensionsEnableHeight)
	require.Equal(t, []string{cmtmldsa65.KeyType}, appGenesis.Consensus.Params.Validator.PubKeyTypes)
	require.Equal(t, app.DefaultBlockMaxGas, appGenesis.Consensus.Params.Block.MaxGas)
	require.NoError(t, appGenesis.Consensus.Params.ValidateBasic())
}

func TestApplyQbtcConsensusParams_NoConsensusParams(t *testing.T) {
	require.Error(t, applyQbtcConsensusParams(&genutiltypes.AppGenesis{}, initArgs{}))
}

// `qbtcd init` writes a genesis with a finite block gas limit, and an app.toml
// with a non-zero minimum gas price.
func TestInitSetsBlockMaxGas(t *testing.T) {
	home := t.TempDir()
	rootCmd := NewRootCmd()
	rootCmd.SetArgs([]string{"init", "test-node", "--chain-id", "qbtc-test-1", "--home", home})
	require.NoError(t, svrcmd.Execute(rootCmd, "", home))

	appGenesis, err := genutiltypes.AppGenesisFromFile(filepath.Join(home, "config", "genesis.json"))
	require.NoError(t, err)
	require.Equal(t, app.DefaultBlockMaxGas, appGenesis.Consensus.Params.Block.MaxGas)
	require.Equal(t, []string{cmtmldsa65.KeyType}, appGenesis.Consensus.Params.Validator.PubKeyTypes)

	appToml, err := os.ReadFile(filepath.Join(home, "config", "app.toml"))
	require.NoError(t, err)
	require.Contains(t, string(appToml), `minimum-gas-prices = "0.0025qbtc"`)
}
