package cmd

import (
	"testing"

	cmtmldsa65 "github.com/cometbft/cometbft/crypto/mldsa65"
	cmttypes "github.com/cometbft/cometbft/types"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	"github.com/stretchr/testify/require"
)

func TestApplyQbtcConsensusParams(t *testing.T) {
	appGenesis := genutiltypes.NewAppGenesisWithVersion("qbtc-test-1", nil)
	appGenesis.Consensus = &genutiltypes.ConsensusGenesis{Params: cmttypes.DefaultConsensusParams()}

	require.NoError(t, applyQbtcConsensusParams(appGenesis, initArgs{voteExtensionsEnableHeight: 2}))

	require.Equal(t, int64(2), appGenesis.Consensus.Params.ABCI.VoteExtensionsEnableHeight)
	require.Equal(t, []string{cmtmldsa65.KeyType}, appGenesis.Consensus.Params.Validator.PubKeyTypes)
	require.NoError(t, appGenesis.Consensus.Params.ValidateBasic())
}

func TestApplyQbtcConsensusParams_NoConsensusParams(t *testing.T) {
	require.Error(t, applyQbtcConsensusParams(&genutiltypes.AppGenesis{}, initArgs{}))
}
