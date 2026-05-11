package keeper_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/stretchr/testify/require"
)

func makeUTXO(txid []byte, vout uint32, amount uint64, address []byte) types.UTXO {
	return types.UTXO{
		Txid:           txid,
		Vout:           vout,
		Amount:         amount,
		EntitledAmount: amount,
		Address:        address,
	}
}

// reverseHexFromWire renders the chain's little-endian txid into the
// big-endian hex form clients send to the query endpoint.
func reverseHexFromWire(b []byte) string {
	rev := make([]byte, len(b))
	for i := range b {
		rev[i] = b[len(b)-1-i]
	}
	return hex.EncodeToString(rev)
}

func TestQueryUTXO(t *testing.T) {
	f := initFixture(t)
	qs := keeper.NewQueryServerImpl(f.keeper)

	txA := bytes.Repeat([]byte{0xaa}, 32)
	txB := bytes.Repeat([]byte{0xbb}, 32)
	txC := bytes.Repeat([]byte{0xcc}, 32)

	utxo1 := makeUTXO(txA, 0, 100000, bytes.Repeat([]byte{0x01}, 20))
	utxo2 := makeUTXO(txA, 1, 200000, bytes.Repeat([]byte{0x02}, 20))
	utxo3 := makeUTXO(txB, 0, 300000, bytes.Repeat([]byte{0x03}, 20))

	for _, u := range []types.UTXO{utxo1, utxo2, utxo3} {
		require.NoError(t, f.keeper.Utxoes.Set(f.ctx, u.GetKey(), u))
	}

	tests := []struct {
		name        string
		req         *types.QueryUTXORequest
		wantTxidHex string
		wantVout    uint32
		wantAmount  uint64
		wantErrIs   error
	}{
		{
			name:        "found - first output of tx a",
			req:         &types.QueryUTXORequest{Txid: reverseHexFromWire(txA), Vout: 0},
			wantTxidHex: reverseHexFromWire(txA),
			wantVout:    0,
			wantAmount:  100000,
		},
		{
			name:        "found - second output of tx a",
			req:         &types.QueryUTXORequest{Txid: reverseHexFromWire(txA), Vout: 1},
			wantTxidHex: reverseHexFromWire(txA),
			wantVout:    1,
			wantAmount:  200000,
		},
		{
			name:        "found - tx b vout 0",
			req:         &types.QueryUTXORequest{Txid: reverseHexFromWire(txB), Vout: 0},
			wantTxidHex: reverseHexFromWire(txB),
			wantVout:    0,
			wantAmount:  300000,
		},
		{
			name:      "not found - unknown txid",
			req:       &types.QueryUTXORequest{Txid: reverseHexFromWire(txC), Vout: 0},
			wantErrIs: sdkerrors.ErrKeyNotFound,
		},
		{
			name:      "not found - wrong vout",
			req:       &types.QueryUTXORequest{Txid: reverseHexFromWire(txA), Vout: 99},
			wantErrIs: sdkerrors.ErrKeyNotFound,
		},
		{
			name:      "nil request",
			req:       nil,
			wantErrIs: sdkerrors.ErrInvalidRequest,
		},
		{
			name:      "empty txid",
			req:       &types.QueryUTXORequest{Txid: "", Vout: 0},
			wantErrIs: sdkerrors.ErrInvalidRequest,
		},
		{
			name:      "txid wrong length",
			req:       &types.QueryUTXORequest{Txid: "abcd", Vout: 0},
			wantErrIs: sdkerrors.ErrInvalidRequest,
		},
		{
			name:      "txid not hex",
			req:       &types.QueryUTXORequest{Txid: "zz" + reverseHexFromWire(txA)[2:], Vout: 0},
			wantErrIs: sdkerrors.ErrInvalidRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := qs.UTXO(f.ctx, tc.req)
			if tc.wantErrIs != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.wantErrIs)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Equal(t, tc.wantTxidHex, resp.Utxo.Txid)
			require.Equal(t, tc.wantVout, resp.Utxo.Vout)
			require.Equal(t, tc.wantAmount, resp.Utxo.Amount)
		})
	}
}
