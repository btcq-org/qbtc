package types_test

import (
	"testing"

	"github.com/btcq-org/qbtc/x/qbtc/types"

	"github.com/stretchr/testify/require"
)

func TestGenesisState_Validate(t *testing.T) {
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
