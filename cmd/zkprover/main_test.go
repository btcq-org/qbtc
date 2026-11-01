package main

import (
	"encoding/hex"
	"testing"

	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
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
	require.Equal(t, "qbtc-claim-v1|qbtc-1|bc1qaddr|qbtc1claimer", target.messageText())
	target.receiver = "qbtc1receiver"
	require.Equal(t, "qbtc-claim-v1|qbtc-1|bc1qaddr|qbtc1receiver", target.messageText())
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
