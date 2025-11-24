package qclient_test

import (
	"context"
	"fmt"
	"testing"

	"cosmossdk.io/math"
	"github.com/btcq-org/qbtc/bifrost/qclient"
	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/stretchr/testify/require"
)

func TestValidatorsVotingPower(t *testing.T) {
	client, err := qclient.New("localhost:9090", true)
	require.NoError(t, err)

	// create random validator vp array
	validators := make([]stakingtypes.Validator, 10)
	for i := range validators {
		validators[i] = stakingtypes.Validator{
			Status:          stakingtypes.Bonded,
			OperatorAddress: sdk.ValAddress(fmt.Sprintf("valoper%d", i)).String(),
			Tokens:          math.NewInt(int64(i+1) * 1_000_000),
		}
	}
	votingPower := client.ValidatorsVotingPower(context.Background(), validators)
	totalShare := math.LegacyZeroDec()
	for _, vp := range votingPower {
		totalShare = totalShare.Add(vp.Share)
	}
	require.True(t, totalShare.Equal(math.LegacyNewDecFromInt(math.NewInt(100))))
}
