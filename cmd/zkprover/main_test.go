package main

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

// TestClaimMsgJSON_RoundTripsThroughChainCodec guards the contract that the
// prove output is loadable by `qbtcd tx qbtc claim-with-proof`, which decodes
// it with the chain's proto codec.
func TestClaimMsgJSON_RoundTripsThroughChainCodec(t *testing.T) {
	target := claimTarget{
		chainID:        "qbtc-1",
		bitcoinAddress: "bc1q4wr4k0uwzryx9jyss3tsd60gaulpxaggzm3mnc",
		claimer:        "qbtc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpz7s0q",
		receiver:       "qbtc1receiver",
		referrer:       "qbtc1referrer",
		utxos: []types.UTXORef{
			{Txid: "0000000000000000000000000000000000000000000000000000000000000001", Vout: 0},
			{Txid: "0000000000000000000000000000000000000000000000000000000000000002", Vout: 3},
		},
	}
	var pubKeyHash [32]byte
	pubKeyHash[0] = 0xab
	proof := []byte{1, 2, 3, 4}

	want := buildClaimMsg(target, proof, pubKeyHash)
	out, err := claimMsgJSON(want)
	require.NoError(t, err)

	cdc := codec.NewProtoCodec(codectypes.NewInterfaceRegistry())
	var got types.MsgClaimWithProof
	require.NoError(t, cdc.UnmarshalJSON(out, &got))
	require.Equal(t, *want, got)
	require.Equal(t, hex.EncodeToString(proof), got.Proof)
	require.Empty(t, got.Broadcaster, "left for the CLI to fill from --from")
}

func TestClaimTarget_Message(t *testing.T) {
	target := claimTarget{chainID: "qbtc-1", bitcoinAddress: "bc1qaddr", claimer: "qbtc1claimer"}
	require.Equal(t, "qbtc-claim-v1|qbtc-1|bc1qaddr|qbtc1claimer|", target.messageText())
	target.receiver = "qbtc1receiver"
	require.Equal(t, "qbtc-claim-v1|qbtc-1|bc1qaddr|qbtc1receiver|", target.messageText())
	target.referrer = "qbtc1referrer"
	require.Equal(t, "qbtc-claim-v1|qbtc-1|bc1qaddr|qbtc1receiver|qbtc1referrer", target.messageText())
}

func TestParseUTXORef(t *testing.T) {
	ref, err := parseUTXORef("00000000000000000000000000000000000000000000000000000000000000aa:7")
	require.NoError(t, err)
	require.Equal(t, types.UTXORef{Txid: "00000000000000000000000000000000000000000000000000000000000000aa", Vout: 7}, ref)

	for _, bad := range []string{"", "abc", "abc:1", "00000000000000000000000000000000000000000000000000000000000000aa", "00000000000000000000000000000000000000000000000000000000000000aa:-1", "00000000000000000000000000000000000000000000000000000000000000aa:x"} {
		_, err := parseUTXORef(bad)
		require.Error(t, err, bad)
	}
}

func TestClaimTarget_Validate(t *testing.T) {
	const canonical = "bc1q4wr4k0uwzryx9jyss3tsd60gaulpxaggzm3mnc"
	target := claimTarget{chainID: "qbtc-1", bitcoinAddress: canonical, claimer: "qbtc1claimer"}
	require.NoError(t, target.validate())

	target.bitcoinAddress = strings.ToUpper(canonical)
	err := target.validate()
	require.Error(t, err, "the chain stores the lowercase form, so the signed text must use it")
	require.Contains(t, err.Error(), canonical)
}

func TestClaimTarget_ValidateReferrer(t *testing.T) {
	claimer := sdk.MustBech32ifyAddressBytes("qbtc", make([]byte, 20))
	referrer := sdk.MustBech32ifyAddressBytes("qbtc", bytes.Repeat([]byte{1}, 20))
	target := claimTarget{
		chainID:        "qbtc-1",
		bitcoinAddress: "bc1q4wr4k0uwzryx9jyss3tsd60gaulpxaggzm3mnc",
		claimer:        claimer,
		referrer:       referrer,
	}
	require.NoError(t, target.validate())

	target.referrer = claimer
	require.ErrorContains(t, target.validate(), "referrer cannot be the claim destination")

	target.referrer = strings.ToUpper(referrer)
	require.ErrorContains(t, target.validate(), "canonical")

	target.referrer = "qbtc1notanaddress"
	require.ErrorContains(t, target.validate(), "--referrer")
}

func TestTSSScalar(t *testing.T) {
	n := btcec.S256().N
	nMinusOne := new(big.Int).Sub(n, big.NewInt(1))
	var canonical [32]byte
	nMinusOne.FillBytes(canonical[:])

	v, scalar, err := tssScalar("R", canonical[:])
	require.NoError(t, err)
	require.Equal(t, 0, v.Cmp(nMinusOne))
	got := scalar.Bytes()
	require.Equal(t, canonical[:], got[:])

	// A DER-style leading zero byte must read as the same value.
	v33, scalar33, err := tssScalar("R", append([]byte{0}, canonical[:]...))
	require.NoError(t, err)
	require.Equal(t, 0, v33.Cmp(v))
	require.True(t, scalar33.Equals(scalar))

	// A short value with leading zeros stripped must read as the same value.
	vShort, scalarShort, err := tssScalar("S", []byte{0x01, 0x02})
	require.NoError(t, err)
	require.Equal(t, int64(0x0102), vShort.Int64())
	var short [32]byte
	short[30], short[31] = 0x01, 0x02
	gotShort := scalarShort.Bytes()
	require.Equal(t, short[:], gotShort[:])

	var nBytes [32]byte
	n.FillBytes(nBytes[:])
	for name, bad := range map[string][]byte{
		"empty":            {},
		"zero":             make([]byte, 32),
		"curve order":      nBytes[:],
		"33 bytes, no pad": append([]byte{1}, canonical[:]...),
	} {
		_, _, err := tssScalar("R", bad)
		require.Error(t, err, name)
	}
}
