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
			desc: "valid airdrop entry",
			genState: &types.GenesisState{
				AirdropEntries: []types.AirdropEntry{
					{
						AddressHash: make([]byte, 20),
						Amount:      1000,
						Claimed:     false,
					},
				},
			},
			valid: true,
		},
		{
			desc: "invalid airdrop entry - wrong hash length",
			genState: &types.GenesisState{
				AirdropEntries: []types.AirdropEntry{
					{
						AddressHash: make([]byte, 19), // wrong length
						Amount:      1000,
					},
				},
			},
			valid:  false,
			errMsg: "invalid address hash length",
		},
		{
			desc: "duplicate airdrop entries",
			genState: &types.GenesisState{
				AirdropEntries: []types.AirdropEntry{
					{
						AddressHash: make([]byte, 20),
						Amount:      1000,
					},
					{
						AddressHash: make([]byte, 20), // duplicate
						Amount:      2000,
					},
				},
			},
			valid:  false,
			errMsg: "duplicate address hash",
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
				ZkVerifyingKey: make([]byte, 200), // valid size but garbage data
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
