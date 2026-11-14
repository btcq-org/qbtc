package types_test

import (
	"os"
	"testing"

	"github.com/btcq-org/qbtc/common"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/stretchr/testify/require"
)

func TestGenesisState_Validate(t *testing.T) {
	// verifying key set up from the Hermez Powers of Tau with the claim circuit's
	// number of public inputs; see x/qbtc/zk/vk_origin_test.go
	hermezVK, err := os.ReadFile("../zk/testdata/hermez08_64public.vk")
	require.NoError(t, err)

	tests := []struct {
		desc     string
		genState *types.GenesisState
		valid    bool
		errMsg   string
	}{
		{
			desc:     "default is valid",
			genState: types.DefaultGenesis(),
			valid:    true,
		},
		{
			desc:     "valid genesis state",
			genState: &types.GenesisState{},
			valid:    true,
		},
		{
			desc: "invalid VK - too small",
			genState: &types.GenesisState{
				ZkVerifyingKey: make([]byte, types.MinVerifyingKeySize-1),
			},
			valid:  false,
			errMsg: "verifying key too small",
		},
		{
			desc: "invalid VK - malformed",
			genState: &types.GenesisState{
				ZkVerifyingKey: make([]byte, types.MinVerifyingKeySize+100), // valid size but garbage data
			},
			valid:  false,
			errMsg: "failed to deserialize verifying key",
		},
		{
			desc: "valid VK from the Hermez Powers of Tau",
			genState: &types.GenesisState{
				ZkVerifyingKey: hermezVK,
			},
			valid: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			err := tc.genState.Validate()
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				if tc.errMsg != "" {
					require.Contains(t, err.Error(), tc.errMsg)
				}
			}
		})
	}
}

func TestGenesisState_ValidateReferralStats(t *testing.T) {
	sdk.GetConfig().SetBech32PrefixForAccount(common.AccountAddressPrefix, common.AccountAddressPrefix+sdk.PrefixPublic)
	addr := sdk.AccAddress(make([]byte, 20)).String()

	valid := types.GenesisState{ReferralStats: []types.ReferralStats{{Address: addr, ReferredClaims: 1, ReferredAmount: 10}}}
	require.NoError(t, valid.Validate())

	bad := types.GenesisState{ReferralStats: []types.ReferralStats{{Address: "nope"}}}
	require.ErrorContains(t, bad.Validate(), "invalid address")

	dup := types.GenesisState{ReferralStats: []types.ReferralStats{{Address: addr}, {Address: addr}}}
	require.ErrorContains(t, dup.Validate(), "duplicate address")
}
