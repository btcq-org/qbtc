package types

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// validBech32Address is a valid cosmos bech32 address for testing
// This is the address format expected by sdk.AccAddressFromBech32
const validBech32Address = "cosmos1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5lzv7xu"

// validBitcoinTxID is a valid 64-character hex Bitcoin transaction ID for testing
const validBitcoinTxID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// validBitcoinTxID2 is another valid 64-character hex Bitcoin transaction ID for testing batch claims
const validBitcoinTxID2 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

// makeValidProof creates a valid proof with proper size for testing
func makeValidProof() string {
	// Create proof data that meets minimum size requirement
	proofData := make([]byte, MinProofSize+100)
	for i := range proofData {
		proofData[i] = byte(i % 256)
	}
	return hex.EncodeToString(proofData)
}

// makeValidUTXORefs creates a slice of UTXORef for testing
func makeValidUTXORefs(count int) []UTXORef {
	refs := make([]UTXORef, count)
	for i := range refs {
		// Create unique txids by modifying the last characters
		txid := validBitcoinTxID[:60] + "000" + string(rune('0'+i%10))
		refs[i] = UTXORef{
			Txid: txid,
			Vout: uint32(i),
		}
	}
	return refs
}

func TestMsgClaimWithProof_ValidateBasic(t *testing.T) {
	testCases := []struct {
		name      string
		msg       *MsgClaimWithProof
		expectErr bool
		errMsg    string
	}{
		{
			name: "valid message - single UTXO",
			msg: &MsgClaimWithProof{
				Claimer: validBech32Address,
				Utxos: []UTXORef{
					{Txid: validBitcoinTxID, Vout: 0},
				},
				Proof: makeValidProof(),
			},
			expectErr: false,
		},
		{
			name: "valid message - multiple UTXOs",
			msg: &MsgClaimWithProof{
				Claimer: validBech32Address,
				Utxos: []UTXORef{
					{Txid: validBitcoinTxID, Vout: 0},
					{Txid: validBitcoinTxID, Vout: 1},
					{Txid: validBitcoinTxID2, Vout: 0},
				},
				Proof: makeValidProof(),
			},
			expectErr: false,
		},
		{
			name: "valid message - max batch size",
			msg: &MsgClaimWithProof{
				Claimer: validBech32Address,
				Utxos:   makeValidUTXORefs(MaxBatchClaimUTXOs),
				Proof:   makeValidProof(),
			},
			expectErr: false,
		},
		{
			name: "missing claimer",
			msg: &MsgClaimWithProof{
				Claimer: "",
				Utxos: []UTXORef{
					{Txid: validBitcoinTxID, Vout: 0},
				},
				Proof: makeValidProof(),
			},
			expectErr: true,
			errMsg:    "claimer address is required",
		},
		{
			name: "invalid claimer address format",
			msg: &MsgClaimWithProof{
				Claimer: "not-a-valid-bech32",
				Utxos: []UTXORef{
					{Txid: validBitcoinTxID, Vout: 0},
				},
				Proof: makeValidProof(),
			},
			expectErr: true,
			errMsg:    "invalid claimer address",
		},
		{
			name: "no UTXOs provided",
			msg: &MsgClaimWithProof{
				Claimer: validBech32Address,
				Utxos:   []UTXORef{},
				Proof:   makeValidProof(),
			},
			expectErr: true,
			errMsg:    "at least one UTXO is required",
		},
		{
			name: "too many UTXOs",
			msg: &MsgClaimWithProof{
				Claimer: validBech32Address,
				Utxos:   makeValidUTXORefs(MaxBatchClaimUTXOs + 1),
				Proof:   makeValidProof(),
			},
			expectErr: true,
			errMsg:    "too many UTXOs in batch",
		},
		{
			name: "missing txid in UTXO",
			msg: &MsgClaimWithProof{
				Claimer: validBech32Address,
				Utxos: []UTXORef{
					{Txid: "", Vout: 0},
				},
				Proof: makeValidProof(),
			},
			expectErr: true,
			errMsg:    "txid is required",
		},
		{
			name: "invalid txid length - too short",
			msg: &MsgClaimWithProof{
				Claimer: validBech32Address,
				Utxos: []UTXORef{
					{Txid: "0123456789abcdef", Vout: 0},
				},
				Proof: makeValidProof(),
			},
			expectErr: true,
			errMsg:    "txid must be 64 hex characters",
		},
		{
			name: "invalid txid - not hex",
			msg: &MsgClaimWithProof{
				Claimer: validBech32Address,
				Utxos: []UTXORef{
					{Txid: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", Vout: 0},
				},
				Proof: makeValidProof(),
			},
			expectErr: true,
			errMsg:    "txid is not valid hex",
		},
		{
			name: "duplicate UTXO references",
			msg: &MsgClaimWithProof{
				Claimer: validBech32Address,
				Utxos: []UTXORef{
					{Txid: validBitcoinTxID, Vout: 0},
					{Txid: validBitcoinTxID, Vout: 0}, // duplicate
				},
				Proof: makeValidProof(),
			},
			expectErr: true,
			errMsg:    "duplicate UTXO reference",
		},
		{
			name: "missing proof data",
			msg: &MsgClaimWithProof{
				Claimer: validBech32Address,
				Utxos: []UTXORef{
					{Txid: validBitcoinTxID, Vout: 0},
				},
				Proof: "",
			},
			expectErr: true,
			errMsg:    "proof data is required",
		},
		{
			name: "nil proof data",
			msg: &MsgClaimWithProof{
				Claimer: validBech32Address,
				Utxos: []UTXORef{
					{Txid: validBitcoinTxID, Vout: 0},
				},
				Proof: "",
			},
			expectErr: true,
			errMsg:    "proof data is required",
		},
		{
			name: "proof data too small",
			msg: &MsgClaimWithProof{
				Claimer: validBech32Address,
				Utxos: []UTXORef{
					{Txid: validBitcoinTxID, Vout: 0},
				},
				Proof: "d6aa", // too small
			},
			expectErr: true,
			errMsg:    "proof data too small",
		},
		{
			name: "proof data too large",
			msg: &MsgClaimWithProof{
				Claimer: validBech32Address,
				Utxos: []UTXORef{
					{Txid: validBitcoinTxID, Vout: 0},
				},
				Proof: makeValidProof() + "invalid extra data",
			},
			expectErr: true,
			errMsg:    "proof data too large",
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
