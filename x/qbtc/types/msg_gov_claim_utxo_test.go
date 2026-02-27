package types

import (
	"testing"

	se "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/stretchr/testify/require"
)

func TestMsgGovClaimUTXO_ValidateBasic(t *testing.T) {
	oversizedUtxos := make([]*ClaimUTXO, MaxBatchClaimUTXOs+1)
	for i := range oversizedUtxos {
		oversizedUtxos[i] = &ClaimUTXO{Txid: "txid", Vout: uint32(i)}
	}

	tests := []struct {
		name string
		msg  MsgGovClaimUTXO
		err  error
	}{
		{name: "default", msg: MsgGovClaimUTXO{Authority: "btcq1...", Utxos: []*ClaimUTXO{{Txid: "txid", Vout: 0}}}},
		{name: "no authority", msg: MsgGovClaimUTXO{Utxos: []*ClaimUTXO{{Txid: "txid", Vout: 0}}}, err: se.ErrInvalidRequest.Wrap("authority is required")},
		{name: "no utxos", msg: MsgGovClaimUTXO{Authority: "btcq1..."}, err: se.ErrInvalidRequest.Wrap("must provide at least one UTXO to claim")},
		{name: "no txid", msg: MsgGovClaimUTXO{Authority: "btcq1...", Utxos: []*ClaimUTXO{{Vout: 0}}}, err: se.ErrInvalidRequest.Wrap("txid is required")},
		{name: "too many utxos", msg: MsgGovClaimUTXO{Authority: "btcq1...", Utxos: oversizedUtxos}, err: se.ErrInvalidRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.msg.ValidateBasic()
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
