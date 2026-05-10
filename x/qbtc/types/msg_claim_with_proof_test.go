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

const validBech32Address = "qbtc1ddffch4l0ynyd8v4q05j9chzqf7dl2pvz9knds"

func makeValidReceiverAddress() string {
	addr := sdk.AccAddress([]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
	})
	return addr.String()
}

func validBitcoinTxID() []byte {
	b, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	return b
}

func validBitcoinTxID2() []byte {
	b, _ := hex.DecodeString("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")
	return b
}

func makeValidProof() string {
	proofData := make([]byte, MinProofSize+100)
	for i := range proofData {
		proofData[i] = byte(i % 256)
	}
	return hex.EncodeToString(proofData)
}

func makeProofBiggerThanMax() string {
	proofData := make([]byte, MaxProofSize+1)
	for i := range proofData {
		proofData[i] = byte(i % 256)
	}
	return hex.EncodeToString(proofData)
}

func makeValidUTXORefs(count int) []UTXORef {
	refs := make([]UTXORef, count)
	for i := range refs {
		txid := make([]byte, 32)
		copy(txid, validBitcoinTxID())
		txid[31] = byte(i)
		refs[i] = UTXORef{
			Txid: txid,
			Vout: uint32(i),
		}
	}
	return refs
}

func makeValidAddressHash() string {
	hash := make([]byte, 20)
	if _, err := rand.Read(hash); err != nil {
		panic(fmt.Sprintf("failed to generate random address hash: %v", err))
	}
	return hex.EncodeToString(hash)
}

func makeValidMessageHash() string {
	hash := make([]byte, 32)
	if _, err := rand.Read(hash); err != nil {
		panic(fmt.Sprintf("failed to generate random message hash: %v", err))
	}
	return hex.EncodeToString(hash)
}

func makeValidQBTCAddressHash() string {
	h := sha256.Sum256([]byte(validBech32Address))
	return hex.EncodeToString(h[:])
}

func makeValidPubKeyHashSHA256() string {
	hash := make([]byte, 32)
	if _, err := rand.Read(hash); err != nil {
		panic(fmt.Sprintf("failed to generate random pubkey hash: %v", err))
	}
	return hex.EncodeToString(hash)
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
				Claimer:          validBech32Address,
				Broadcaster:      validBech32Address,
				Utxos:            []UTXORef{{Txid: validBitcoinTxID(), Vout: 0}},
				MessageHash:      makeValidMessageHash(),
				AddressHash:      makeValidAddressHash(),
				QbtcAddressHash:  makeValidQBTCAddressHash(),
				PubKeyHashSha256: makeValidPubKeyHashSHA256(),
				Proof:            makeValidProof(),
			},
			expectErr: false,
		},
		{
			name: "valid message - broadcaster differs from claimer",
			msg: &MsgClaimWithProof{
				Claimer:          validBech32Address,
				Broadcaster:      makeValidReceiverAddress(),
				Utxos:            []UTXORef{{Txid: validBitcoinTxID(), Vout: 0}},
				MessageHash:      makeValidMessageHash(),
				AddressHash:      makeValidAddressHash(),
				QbtcAddressHash:  makeValidQBTCAddressHash(),
				PubKeyHashSha256: makeValidPubKeyHashSHA256(),
				Proof:            makeValidProof(),
			},
			expectErr: false,
		},
		{
			name: "valid message - multiple UTXOs",
			msg: &MsgClaimWithProof{
				Claimer:     validBech32Address,
				Broadcaster: validBech32Address,
				Utxos: []UTXORef{
					{Txid: validBitcoinTxID(), Vout: 0},
					{Txid: validBitcoinTxID(), Vout: 1},
					{Txid: validBitcoinTxID2(), Vout: 0},
				},
				MessageHash:      makeValidMessageHash(),
				AddressHash:      makeValidAddressHash(),
				QbtcAddressHash:  makeValidQBTCAddressHash(),
				PubKeyHashSha256: makeValidPubKeyHashSHA256(),
				Proof:            makeValidProof(),
			},
			expectErr: false,
		},
		{
			name: "valid message - max batch size",
			msg: &MsgClaimWithProof{
				Claimer:          validBech32Address,
				Broadcaster:      validBech32Address,
				Utxos:            makeValidUTXORefs(MaxBatchClaimUTXOs),
				MessageHash:      makeValidMessageHash(),
				AddressHash:      makeValidAddressHash(),
				QbtcAddressHash:  makeValidQBTCAddressHash(),
				PubKeyHashSha256: makeValidPubKeyHashSHA256(),
				Proof:            makeValidProof(),
			},
			expectErr: false,
		},
		{
			name: "valid message - with receiver",
			msg: &MsgClaimWithProof{
				Claimer:          validBech32Address,
				Broadcaster:      validBech32Address,
				Receiver:         makeValidReceiverAddress(),
				Utxos:            []UTXORef{{Txid: validBitcoinTxID(), Vout: 0}},
				MessageHash:      makeValidMessageHash(),
				AddressHash:      makeValidAddressHash(),
				QbtcAddressHash:  makeValidQBTCAddressHash(),
				PubKeyHashSha256: makeValidPubKeyHashSHA256(),
				Proof:            makeValidProof(),
			},
			expectErr: false,
		},
		{
			name: "invalid receiver address",
			msg: &MsgClaimWithProof{
				Claimer:          validBech32Address,
				Broadcaster:      validBech32Address,
				Receiver:         "not-a-valid-bech32",
				Utxos:            []UTXORef{{Txid: validBitcoinTxID(), Vout: 0}},
				MessageHash:      makeValidMessageHash(),
				AddressHash:      makeValidAddressHash(),
				QbtcAddressHash:  makeValidQBTCAddressHash(),
				PubKeyHashSha256: makeValidPubKeyHashSHA256(),
				Proof:            makeValidProof(),
			},
			expectErr: true,
			errMsg:    "invalid receiver address",
		},
		{
			name: "missing broadcaster",
			msg: &MsgClaimWithProof{
				Claimer:          validBech32Address,
				Broadcaster:      "",
				Utxos:            []UTXORef{{Txid: validBitcoinTxID(), Vout: 0}},
				MessageHash:      makeValidMessageHash(),
				AddressHash:      makeValidAddressHash(),
				QbtcAddressHash:  makeValidQBTCAddressHash(),
				PubKeyHashSha256: makeValidPubKeyHashSHA256(),
				Proof:            makeValidProof(),
			},
			expectErr: true,
			errMsg:    "broadcaster address is required",
		},
		{
			name: "invalid broadcaster address format",
			msg: &MsgClaimWithProof{
				Claimer:          validBech32Address,
				Broadcaster:      "not-a-valid-bech32",
				Utxos:            []UTXORef{{Txid: validBitcoinTxID(), Vout: 0}},
				MessageHash:      makeValidMessageHash(),
				AddressHash:      makeValidAddressHash(),
				QbtcAddressHash:  makeValidQBTCAddressHash(),
				PubKeyHashSha256: makeValidPubKeyHashSHA256(),
				Proof:            makeValidProof(),
			},
			expectErr: true,
			errMsg:    "invalid broadcaster address",
		},
		{
			name: "missing claimer",
			msg: &MsgClaimWithProof{
				Claimer: "",
				Utxos: []UTXORef{
					{Txid: validBitcoinTxID(), Vout: 0},
				},
				MessageHash:      makeValidMessageHash(),
				AddressHash:      makeValidAddressHash(),
				QbtcAddressHash:  makeValidQBTCAddressHash(),
				PubKeyHashSha256: makeValidPubKeyHashSHA256(),
				Proof:            makeValidProof(),
			},
			expectErr: true,
			errMsg:    "claimer address is required",
		},
		{
			name: "invalid claimer address format",
			msg: &MsgClaimWithProof{
				Claimer: "not-a-valid-bech32",
				Utxos: []UTXORef{
					{Txid: validBitcoinTxID(), Vout: 0},
				},
				MessageHash:      makeValidMessageHash(),
				AddressHash:      makeValidAddressHash(),
				QbtcAddressHash:  makeValidQBTCAddressHash(),
				PubKeyHashSha256: makeValidPubKeyHashSHA256(),
				Proof:            makeValidProof(),
			},
			expectErr: true,
			errMsg:    "invalid claimer address",
		},
		{
			name: "no UTXOs provided",
			msg: &MsgClaimWithProof{
				Claimer:          validBech32Address,
				Broadcaster:      validBech32Address,
				Utxos:            []UTXORef{},
				MessageHash:      makeValidMessageHash(),
				AddressHash:      makeValidAddressHash(),
				QbtcAddressHash:  makeValidQBTCAddressHash(),
				PubKeyHashSha256: makeValidPubKeyHashSHA256(),
				Proof:            makeValidProof(),
			},
			expectErr: true,
			errMsg:    "at least one UTXO is required",
		},
		{
			name: "too many UTXOs",
			msg: &MsgClaimWithProof{
				Claimer:          validBech32Address,
				Broadcaster:      validBech32Address,
				Utxos:            makeValidUTXORefs(MaxBatchClaimUTXOs + 1),
				MessageHash:      makeValidMessageHash(),
				AddressHash:      makeValidAddressHash(),
				QbtcAddressHash:  makeValidQBTCAddressHash(),
				PubKeyHashSha256: makeValidPubKeyHashSHA256(),
				Proof:            makeValidProof(),
			},
			expectErr: true,
			errMsg:    "too many UTXOs in batch",
		},
		{
			name: "missing txid in UTXO",
			msg: &MsgClaimWithProof{
				Claimer:     validBech32Address,
				Broadcaster: validBech32Address,
				Utxos: []UTXORef{
					{Txid: nil, Vout: 0},
				},
				Proof: makeValidProof(),
			},
			expectErr: true,
			errMsg:    "txid must be 32 bytes",
		},
		{
			name: "invalid txid length - too short",
			msg: &MsgClaimWithProof{
				Claimer:     validBech32Address,
				Broadcaster: validBech32Address,
				Utxos: []UTXORef{
					{Txid: []byte{0x01, 0x02}, Vout: 0},
				},
				MessageHash:      makeValidMessageHash(),
				AddressHash:      makeValidAddressHash(),
				QbtcAddressHash:  makeValidQBTCAddressHash(),
				PubKeyHashSha256: makeValidPubKeyHashSHA256(),
				Proof:            makeValidProof(),
			},
			expectErr: true,
			errMsg:    "txid must be 32 bytes",
		},
		{
			name: "duplicate UTXO references",
			msg: &MsgClaimWithProof{
				Claimer:     validBech32Address,
				Broadcaster: validBech32Address,
				Utxos: []UTXORef{
					{Txid: validBitcoinTxID(), Vout: 0},
					{Txid: validBitcoinTxID(), Vout: 0},
				},
				MessageHash:      makeValidMessageHash(),
				AddressHash:      makeValidAddressHash(),
				QbtcAddressHash:  makeValidQBTCAddressHash(),
				PubKeyHashSha256: makeValidPubKeyHashSHA256(),
				Proof:            makeValidProof(),
			},
			expectErr: true,
			errMsg:    "duplicate UTXO reference",
		},
		{
			name: "missing proof data",
			msg: &MsgClaimWithProof{
				Claimer:     validBech32Address,
				Broadcaster: validBech32Address,
				Utxos:       []UTXORef{{Txid: validBitcoinTxID(), Vout: 0}},
				MessageHash:      makeValidMessageHash(),
				AddressHash:      makeValidAddressHash(),
				QbtcAddressHash:  makeValidQBTCAddressHash(),
				PubKeyHashSha256: makeValidPubKeyHashSHA256(),
				Proof:            "",
			},
			expectErr: true,
			errMsg:    "proof data is required",
		},
		{
			name: "proof data too small",
			msg: &MsgClaimWithProof{
				Claimer:     validBech32Address,
				Broadcaster: validBech32Address,
				Utxos:       []UTXORef{{Txid: validBitcoinTxID(), Vout: 0}},
				MessageHash:      makeValidMessageHash(),
				AddressHash:      makeValidAddressHash(),
				QbtcAddressHash:  makeValidQBTCAddressHash(),
				PubKeyHashSha256: makeValidPubKeyHashSHA256(),
				Proof:            "d6aa",
			},
			expectErr: true,
			errMsg:    "proof data too small",
		},
		{
			name: "proof data too large",
			msg: &MsgClaimWithProof{
				Claimer:     validBech32Address,
				Broadcaster: validBech32Address,
				Utxos:       []UTXORef{{Txid: validBitcoinTxID(), Vout: 0}},
				MessageHash:      makeValidMessageHash(),
				AddressHash:      makeValidAddressHash(),
				QbtcAddressHash:  makeValidQBTCAddressHash(),
				PubKeyHashSha256: makeValidPubKeyHashSHA256(),
				Proof:            makeProofBiggerThanMax(),
			},
			expectErr: true,
			errMsg:    "proof data too large",
		},
		{
			name: "invalid message - no message hash",
			msg: &MsgClaimWithProof{
				Claimer:     validBech32Address,
				Broadcaster: validBech32Address,
				Utxos:       []UTXORef{{Txid: validBitcoinTxID(), Vout: 0}},
				MessageHash:      "",
				AddressHash:      makeValidAddressHash(),
				QbtcAddressHash:  makeValidQBTCAddressHash(),
				PubKeyHashSha256: makeValidPubKeyHashSHA256(),
				Proof:            makeValidProof(),
			},
			expectErr: true,
			errMsg:    "message_hash must be 64 hex characters",
		},
		{
			name: "invalid message - no qbtc address hash",
			msg: &MsgClaimWithProof{
				Claimer:     validBech32Address,
				Broadcaster: validBech32Address,
				Utxos:       []UTXORef{{Txid: validBitcoinTxID(), Vout: 0}},
				MessageHash:      makeValidMessageHash(),
				AddressHash:      makeValidAddressHash(),
				QbtcAddressHash:  "",
				PubKeyHashSha256: makeValidPubKeyHashSHA256(),
				Proof:            makeValidProof(),
			},
			expectErr: true,
			errMsg:    "qbtc_address_hash is required",
		},
		{
			name: "invalid message - no pub_key_hash_sha256",
			msg: &MsgClaimWithProof{
				Claimer:     validBech32Address,
				Broadcaster: validBech32Address,
				Utxos:       []UTXORef{{Txid: validBitcoinTxID(), Vout: 0}},
				MessageHash:      makeValidMessageHash(),
				AddressHash:      makeValidAddressHash(),
				QbtcAddressHash:  makeValidQBTCAddressHash(),
				PubKeyHashSha256: "",
				Proof:            makeValidProof(),
			},
			expectErr: true,
			errMsg:    "pub_key_hash_sha256 must be 64 hex characters",
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
