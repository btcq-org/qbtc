package keeper_test

import (
	"testing"

	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/stretchr/testify/require"
)

func makeUTXO(txid string, vout uint32, amount uint64, address string) types.UTXO {
	return types.UTXO{
		Txid:           txid,
		Vout:           vout,
		Amount:         amount,
		EntitledAmount: amount,
		ScriptPubKey: &types.ScriptPubKeyResult{
			Address: address,
			Type:    "pubkeyhash",
			Hex:     "76a914" + txid[:14] + "88ac",
		},
	}
}

func TestQueryUTXO(t *testing.T) {
	f := initFixture(t)
	qs := keeper.NewQueryServerImpl(f.keeper)

	utxo1 := makeUTXO("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0, 100000, "bc1qaddr1")
	utxo2 := makeUTXO("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1, 200000, "bc1qaddr2")
	utxo3 := makeUTXO("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 0, 300000, "bc1qaddr3")

	for _, u := range []types.UTXO{utxo1, utxo2, utxo3} {
		require.NoError(t, f.keeper.Utxoes.Set(f.ctx, u.GetKey(), u))
	}

	tests := []struct {
		name      string
		req       *types.QueryUTXORequest
		wantUTXO  *types.UTXO
		wantErrIs error
	}{
		{
			name:     "found - first output of tx a",
			req:      &types.QueryUTXORequest{Txid: utxo1.Txid, Vout: 0},
			wantUTXO: &utxo1,
		},
		{
			name:     "found - second output of tx a",
			req:      &types.QueryUTXORequest{Txid: utxo2.Txid, Vout: 1},
			wantUTXO: &utxo2,
		},
		{
			name:     "found - tx b vout 0",
			req:      &types.QueryUTXORequest{Txid: utxo3.Txid, Vout: 0},
			wantUTXO: &utxo3,
		},
		{
			name:      "not found - unknown txid",
			req:       &types.QueryUTXORequest{Txid: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", Vout: 0},
			wantErrIs: sdkerrors.ErrKeyNotFound,
		},
		{
			name:      "not found - wrong vout",
			req:       &types.QueryUTXORequest{Txid: utxo1.Txid, Vout: 99},
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
			require.Equal(t, tc.wantUTXO.Txid, resp.Utxo.Txid)
			require.Equal(t, tc.wantUTXO.Vout, resp.Utxo.Vout)
			require.Equal(t, tc.wantUTXO.Amount, resp.Utxo.Amount)
		})
	}
}
