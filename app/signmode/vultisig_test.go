package signmode_test

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cosmos/cosmos-sdk/x/tx/signing"
	"github.com/cosmos/cosmos-sdk/x/tx/signing/direct"

	"github.com/btcq-org/qbtc/app/signmode"
)

func TestVultisigSignModeHandler(t *testing.T) {
	h := signmode.VultisigSignModeHandler{}
	require.EqualValues(t, 1000, h.Mode())

	signerData := signing.SignerData{ChainID: "qbtc-testnet-1", AccountNumber: 9591234282079533897, Sequence: 3}
	txData := signing.TxData{BodyBytes: []byte{0x0a, 0x01, 0x02}, AuthInfoBytes: []byte{0x12, 0x03, 0x04}}

	signDoc, err := direct.SignModeHandler{}.GetSignBytes(context.Background(), signerData, txData)
	require.NoError(t, err)
	want := sha256.Sum256(signDoc)

	got, err := h.GetSignBytes(context.Background(), signerData, txData)
	require.NoError(t, err)
	require.Equal(t, want[:], got)
	require.Len(t, got, 32)
}
