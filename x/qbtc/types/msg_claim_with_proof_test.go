package types

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/btcq-org/qbtc/common"
	"github.com/btcq-org/qbtc/x/qbtc/zk"
	"github.com/btcq-org/qbtc/x/qbtc/zk/zktest"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

// validBech32Address is a valid cosmos bech32 address for testing
// This is the address format expected by sdk.AccAddressFromBech32
const validBech32Address = "qbtc1ddffch4l0ynyd8v4q05j9chzqf7dl2pvz9knds"

// makeValidReceiverAddress returns a valid bech32 address distinct from validBech32Address.
// Must be called after the bech32 prefix has been configured in the SDK.
func makeValidReceiverAddress() string {
	addr := sdk.AccAddress([]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
	})
	return addr.String()
}

// validBitcoinTxID is a valid 64-character hex Bitcoin transaction ID for testing
const validBitcoinTxID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// validBitcoinTxID2 is another valid 64-character hex Bitcoin transaction ID for testing batch claims
const validBitcoinTxID2 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

// makeValidProof returns a hex proof with the claim circuit's layout. It
// passes ValidateBasic but would fail PLONK verification.
func makeValidProof() string {
	return hex.EncodeToString(zktest.WellFormedProof(zk.ClaimCircuitNbCommitments))
}

// makeProofWithBsb22Prefix returns a correctly sized hex proof whose
// Bsb22Commitments length prefix, its last 4 bytes before the commitment
// points, is set to count.
func makeProofWithBsb22Prefix(count uint32) string {
	proof := zktest.WellFormedProof(zk.ClaimCircuitNbCommitments)
	off := len(proof) - 4 - zk.ClaimCircuitNbCommitments*32
	binary.BigEndian.PutUint32(proof[off:], count)
	return hex.EncodeToString(proof)
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

// makeValidPubKeyHashSHA256 creates a valid 64-character hex value (32 bytes)
// for the SHA256(SEC-compressed pubkey) public input to the ZK circuit.
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
				Utxos:            []UTXORef{{Txid: validBitcoinTxID, Vout: 0}},
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
				Utxos:            []UTXORef{{Txid: validBitcoinTxID, Vout: 0}},
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
					{Txid: validBitcoinTxID, Vout: 0},
					{Txid: validBitcoinTxID, Vout: 1},
					{Txid: validBitcoinTxID2, Vout: 0},
				},
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
				Utxos:            []UTXORef{{Txid: validBitcoinTxID, Vout: 0}},
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
				Utxos:            []UTXORef{{Txid: validBitcoinTxID, Vout: 0}},
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
				Utxos:            []UTXORef{{Txid: validBitcoinTxID, Vout: 0}},
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
				Utxos:            []UTXORef{{Txid: validBitcoinTxID, Vout: 0}},
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
					{Txid: validBitcoinTxID, Vout: 0},
				},
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
					{Txid: validBitcoinTxID, Vout: 0},
				},
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
				Utxos:       []UTXORef{{Txid: "", Vout: 0}},
				Proof:       makeValidProof(),
			},
			expectErr: true,
			errMsg:    "txid is required",
		},
		{
			name: "invalid txid length - too short",
			msg: &MsgClaimWithProof{
				Claimer:          validBech32Address,
				Broadcaster:      validBech32Address,
				Utxos:            []UTXORef{{Txid: "0123456789abcdef", Vout: 0}},
				PubKeyHashSha256: makeValidPubKeyHashSHA256(),
				Proof:            makeValidProof(),
			},
			expectErr: true,
			errMsg:    "txid must be 64 hex characters",
		},
		{
			name: "invalid txid - not hex",
			msg: &MsgClaimWithProof{
				Claimer:     validBech32Address,
				Broadcaster: validBech32Address,
				Utxos: []UTXORef{
					{Txid: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", Vout: 0},
				},
				PubKeyHashSha256: makeValidPubKeyHashSHA256(),
				Proof:            makeValidProof(),
			},
			expectErr: true,
			errMsg:    "txid is not valid hex",
		},
		{
			name: "duplicate UTXO references",
			msg: &MsgClaimWithProof{
				Claimer:     validBech32Address,
				Broadcaster: validBech32Address,
				Utxos: []UTXORef{
					{Txid: validBitcoinTxID, Vout: 0},
					{Txid: validBitcoinTxID, Vout: 0}, // duplicate
				},
				PubKeyHashSha256: makeValidPubKeyHashSHA256(),
				Proof:            makeValidProof(),
			},
			expectErr: true,
			errMsg:    "duplicate UTXO reference",
		},
		{
			name: "missing proof data",
			msg: &MsgClaimWithProof{
				Claimer:          validBech32Address,
				Broadcaster:      validBech32Address,
				Utxos:            []UTXORef{{Txid: validBitcoinTxID, Vout: 0}},
				PubKeyHashSha256: makeValidPubKeyHashSHA256(),
				Proof:            "",
			},
			expectErr: true,
			errMsg:    "proof data is required",
		},
		{
			name: "proof data too small",
			msg: &MsgClaimWithProof{
				Claimer:          validBech32Address,
				Broadcaster:      validBech32Address,
				Utxos:            []UTXORef{{Txid: validBitcoinTxID, Vout: 0}},
				PubKeyHashSha256: makeValidPubKeyHashSHA256(),
				Proof:            "d6aa",
			},
			expectErr: true,
			errMsg:    "proof data is 4 hex characters, want 1168",
		},
		{
			name: "proof data too large",
			msg: &MsgClaimWithProof{
				Claimer:          validBech32Address,
				Broadcaster:      validBech32Address,
				Utxos:            []UTXORef{{Txid: validBitcoinTxID, Vout: 0}},
				PubKeyHashSha256: makeValidPubKeyHashSHA256(),
				Proof:            makeValidProof() + "00",
			},
			expectErr: true,
			errMsg:    "proof data is 1170 hex characters, want 1168",
		},
		{
			name: "proof data not hex",
			msg: &MsgClaimWithProof{
				Claimer:          validBech32Address,
				Broadcaster:      validBech32Address,
				Utxos:            []UTXORef{{Txid: validBitcoinTxID, Vout: 0}},
				PubKeyHashSha256: makeValidPubKeyHashSHA256(),
				Proof:            strings.Repeat("zz", 584),
			},
			expectErr: true,
			errMsg:    "proof data is not valid hex",
		},
		{
			name: "proof with huge Bsb22Commitments count",
			msg: &MsgClaimWithProof{
				Claimer:          validBech32Address,
				Broadcaster:      validBech32Address,
				Utxos:            []UTXORef{{Txid: validBitcoinTxID, Vout: 0}},
				PubKeyHashSha256: makeValidPubKeyHashSHA256(),
				Proof:            makeProofWithBsb22Prefix(0xFFFFFFFF),
			},
			expectErr: true,
			errMsg:    "Bsb22Commitments count is 4294967295",
		},
		{
			name: "proof with no Bsb22Commitments",
			msg: &MsgClaimWithProof{
				Claimer:          validBech32Address,
				Broadcaster:      validBech32Address,
				Utxos:            []UTXORef{{Txid: validBitcoinTxID, Vout: 0}},
				PubKeyHashSha256: makeValidPubKeyHashSHA256(),
				Proof:            makeProofWithBsb22Prefix(0),
			},
			expectErr: true,
			errMsg:    "Bsb22Commitments count is 0",
		},
		{
			name: "invalid message - no pub_key_hash_sha256",
			msg: &MsgClaimWithProof{
				Claimer:          validBech32Address,
				Broadcaster:      validBech32Address,
				Utxos:            []UTXORef{{Txid: validBitcoinTxID, Vout: 0}},
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

func TestMsgClaimWithProof_ValidateBasic_Referrer(t *testing.T) {
	sdk.GetConfig().SetBech32PrefixForAccount(common.AccountAddressPrefix, common.AccountAddressPrefix+sdk.PrefixPublic)
	receiver := makeValidReceiverAddress()
	referrer := sdk.AccAddress(make([]byte, 20)).String()

	newMsg := func(receiver, referrer string) *MsgClaimWithProof {
		return &MsgClaimWithProof{
			Claimer:          validBech32Address,
			Broadcaster:      validBech32Address,
			Receiver:         receiver,
			Referrer:         referrer,
			Utxos:            []UTXORef{{Txid: validBitcoinTxID, Vout: 0}},
			PubKeyHashSha256: makeValidPubKeyHashSHA256(),
			Proof:            makeValidProof(),
		}
	}

	testCases := []struct {
		name     string
		receiver string
		referrer string
		errMsg   string
	}{
		{name: "no referrer", receiver: "", referrer: ""},
		{name: "referrer distinct from claimer", receiver: "", referrer: referrer},
		{name: "referrer distinct from receiver", receiver: receiver, referrer: referrer},
		{name: "referrer may be the claimer when coins go to a receiver", receiver: receiver, referrer: validBech32Address},
		{name: "referrer is not bech32", referrer: "not-an-address", errMsg: "invalid referrer address"},
		{name: "referrer has the wrong prefix", referrer: "cosmos1ddffch4l0ynyd8v4q05j9chzqf7dl2pvz9knds", errMsg: "invalid referrer address"},
		{name: "referrer spelled in upper case", referrer: strings.ToUpper(referrer), errMsg: "canonical"},
		{name: "referrer is the claimer destination", referrer: validBech32Address, errMsg: "referrer cannot be the claim destination"},
		{name: "referrer is the receiver destination", receiver: receiver, referrer: receiver, errMsg: "referrer cannot be the claim destination"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := newMsg(tc.receiver, tc.referrer).ValidateBasic()
			if tc.errMsg == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.errMsg)
		})
	}
}

func TestMsgClaimWithProof_Destination(t *testing.T) {
	require.Equal(t, "claimer", (&MsgClaimWithProof{Claimer: "claimer"}).Destination())
	require.Equal(t, "receiver", (&MsgClaimWithProof{Claimer: "claimer", Receiver: "receiver"}).Destination())
}
