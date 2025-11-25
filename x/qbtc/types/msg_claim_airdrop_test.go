package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMsgClaimAirdrop_ValidateBasic(t *testing.T) {
	testCases := []struct {
		name      string
		msg       *MsgClaimAirdrop
		expectErr bool
		errMsg    string
	}{
		{
			name: "valid message",
			msg: &MsgClaimAirdrop{
				Claimer:        "qbtc1abc123def456",
				BtcAddressHash: make([]byte, 20),
				Proof: ZKProof{
					ProofData:    []byte{1, 2, 3, 4},
					PublicInputs: [][]byte{{1, 2}},
				},
			},
			expectErr: false,
		},
		{
			name: "missing claimer",
			msg: &MsgClaimAirdrop{
				Claimer:        "",
				BtcAddressHash: make([]byte, 20),
				Proof: ZKProof{
					ProofData: []byte{1, 2, 3, 4},
				},
			},
			expectErr: true,
			errMsg:    "claimer address is required",
		},
		{
			name: "invalid address hash length - too short",
			msg: &MsgClaimAirdrop{
				Claimer:        "qbtc1abc123def456",
				BtcAddressHash: make([]byte, 19),
				Proof: ZKProof{
					ProofData: []byte{1, 2, 3, 4},
				},
			},
			expectErr: true,
			errMsg:    "btc_address_hash must be 20 bytes",
		},
		{
			name: "invalid address hash length - too long",
			msg: &MsgClaimAirdrop{
				Claimer:        "qbtc1abc123def456",
				BtcAddressHash: make([]byte, 21),
				Proof: ZKProof{
					ProofData: []byte{1, 2, 3, 4},
				},
			},
			expectErr: true,
			errMsg:    "btc_address_hash must be 20 bytes",
		},
		{
			name: "missing proof data",
			msg: &MsgClaimAirdrop{
				Claimer:        "qbtc1abc123def456",
				BtcAddressHash: make([]byte, 20),
				Proof: ZKProof{
					ProofData: []byte{},
				},
			},
			expectErr: true,
			errMsg:    "proof data is required",
		},
		{
			name: "nil proof data",
			msg: &MsgClaimAirdrop{
				Claimer:        "qbtc1abc123def456",
				BtcAddressHash: make([]byte, 20),
				Proof:          ZKProof{},
			},
			expectErr: true,
			errMsg:    "proof data is required",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.msg.ValidateBasic()
			if tc.expectErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestMsgClaimAirdrop_BtcAddressHashHex(t *testing.T) {
	msg := &MsgClaimAirdrop{
		BtcAddressHash: []byte{
			0x01, 0x02, 0x03, 0x04, 0x05,
			0x06, 0x07, 0x08, 0x09, 0x0a,
			0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14,
		},
	}

	expected := "0102030405060708090a0b0c0d0e0f1011121314"
	require.Equal(t, expected, msg.BtcAddressHashHex())
}
