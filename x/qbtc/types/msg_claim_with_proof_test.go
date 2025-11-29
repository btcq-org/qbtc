package types

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/btcq-org/qbtc/common"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

// validBech32Address is a valid cosmos bech32 address for testing
// This is the address format expected by sdk.AccAddressFromBech32
const validBech32Address = "qbtc1ddffch4l0ynyd8v4q05j9chzqf7dl2pvz9knds"

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
func makeProofBiggerThanMax() string {
	// Create proof data that exceeds maximum size requirement
	proofData := make([]byte, MaxProofSize+1)
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

// makeValidAddressHash creates a valid 40-character hex address hash (20 bytes)
func makeValidAddressHash() string {
	hash := make([]byte, 20) // Bitcoin address hash is 20 bytes (RIPEMD160)
	_, err := rand.Read(hash)
	if err != nil {
		panic(fmt.Sprintf("failed to generate random address hash: %v", err))
	}
	return hex.EncodeToString(hash) // 40 hex characters
}

// makeValidMessageHash creates a valid 64-character hex message hash (32 bytes)
func makeValidMessageHash() string {
	hash := make([]byte, 32) // SHA256 hash is 32 bytes
	_, err := rand.Read(hash)
	if err != nil {
		panic(fmt.Sprintf("failed to generate random message hash: %v", err))
	}
	return hex.EncodeToString(hash) // 64 hex characters
}
func makeValidQBTCAddressHash() string {
	return hex.EncodeToString(sha256.New().Sum([]byte(validBech32Address)))
}
func TestMsgClaimWithProof_ValidateBasic(t *testing.T) {
	sdk.GetConfig().SetBech32PrefixForAccount(common.AccountAddressPrefix, common.AccountAddressPrefix+sdk.PrefixPublic)
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
				MessageHash:     makeValidMessageHash(),
				AddressHash:     makeValidAddressHash(),
				QbtcAddressHash: makeValidQBTCAddressHash(),
				Proof:           makeValidProof(),
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
				MessageHash:     makeValidMessageHash(),
				AddressHash:     makeValidAddressHash(),
				QbtcAddressHash: makeValidQBTCAddressHash(),
				Proof:           makeValidProof(),
			},
			expectErr: false,
		},
		{
			name: "valid message - max batch size",
			msg: &MsgClaimWithProof{
				Claimer:         validBech32Address,
				Utxos:           makeValidUTXORefs(MaxBatchClaimUTXOs),
				MessageHash:     makeValidMessageHash(),
				AddressHash:     makeValidAddressHash(),
				QbtcAddressHash: makeValidQBTCAddressHash(),
				Proof:           makeValidProof(),
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
				MessageHash:     makeValidMessageHash(),
				AddressHash:     makeValidAddressHash(),
				QbtcAddressHash: makeValidQBTCAddressHash(),
				Proof:           makeValidProof(),
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
				MessageHash:     makeValidMessageHash(),
				AddressHash:     makeValidAddressHash(),
				QbtcAddressHash: makeValidQBTCAddressHash(),
				Proof:           makeValidProof(),
			},
			expectErr: true,
			errMsg:    "invalid claimer address",
		},
		{
			name: "no UTXOs provided",
			msg: &MsgClaimWithProof{
				Claimer:         validBech32Address,
				Utxos:           []UTXORef{},
				MessageHash:     makeValidMessageHash(),
				AddressHash:     makeValidAddressHash(),
				QbtcAddressHash: makeValidQBTCAddressHash(),
				Proof:           makeValidProof(),
			},
			expectErr: true,
			errMsg:    "at least one UTXO is required",
		},
		{
			name: "too many UTXOs",
			msg: &MsgClaimWithProof{
				Claimer:         validBech32Address,
				Utxos:           makeValidUTXORefs(MaxBatchClaimUTXOs + 1),
				MessageHash:     makeValidMessageHash(),
				AddressHash:     makeValidAddressHash(),
				QbtcAddressHash: makeValidQBTCAddressHash(),
				Proof:           makeValidProof(),
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
				MessageHash:     makeValidMessageHash(),
				AddressHash:     makeValidAddressHash(),
				QbtcAddressHash: makeValidQBTCAddressHash(),
				Proof:           makeValidProof(),
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
				MessageHash:     makeValidMessageHash(),
				AddressHash:     makeValidAddressHash(),
				QbtcAddressHash: makeValidQBTCAddressHash(),
				Proof:           makeValidProof(),
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
				MessageHash:     makeValidMessageHash(),
				AddressHash:     makeValidAddressHash(),
				QbtcAddressHash: makeValidQBTCAddressHash(),
				Proof:           makeValidProof(),
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
				MessageHash:     makeValidMessageHash(),
				AddressHash:     makeValidAddressHash(),
				QbtcAddressHash: makeValidQBTCAddressHash(),
				Proof:           "",
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
				MessageHash:     makeValidMessageHash(),
				AddressHash:     makeValidAddressHash(),
				QbtcAddressHash: makeValidQBTCAddressHash(),
				Proof:           "d6aa", // too small
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
				MessageHash:     makeValidMessageHash(),
				AddressHash:     makeValidAddressHash(),
				QbtcAddressHash: makeValidQBTCAddressHash(),
				Proof:           makeProofBiggerThanMax(),
			},
			expectErr: true,
			errMsg:    "proof data too large",
		},
		{
			name: "invalid message - no message hash",
			msg: &MsgClaimWithProof{
				Claimer: validBech32Address,
				Utxos: []UTXORef{
					{Txid: validBitcoinTxID, Vout: 0},
				},
				MessageHash:     "",
				AddressHash:     makeValidAddressHash(),
				QbtcAddressHash: makeValidQBTCAddressHash(),
				Proof:           makeValidProof(),
			},
			expectErr: true,
			errMsg:    "message_hash must be 64 hex characters",
		},
		{
			name: "invalid message - no address hash",
			msg: &MsgClaimWithProof{
				Claimer: validBech32Address,
				Utxos: []UTXORef{
					{Txid: validBitcoinTxID, Vout: 0},
				},
				MessageHash:     makeValidMessageHash(),
				AddressHash:     makeValidAddressHash(),
				QbtcAddressHash: "",
				Proof:           makeValidProof(),
			},
			expectErr: true,
			errMsg:    "qbtc_address_hash is required",
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
