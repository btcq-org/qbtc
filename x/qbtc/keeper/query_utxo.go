package keeper

import (
	"context"
	"encoding/hex"
	"errors"

	"cosmossdk.io/collections"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

// UTXO answers gRPC/REST UTXO queries. The request carries the txid in the
// big-endian hex form block explorers show; the handler reverses to the
// chain's internal little-endian wire representation before looking up state.
// The response is a DisplayUTXO with hex-encoded txid and address so REST/JSON
// clients don't have to base64-decode the storage form.
func (qs queryServer) UTXO(ctx context.Context, req *types.QueryUTXORequest) (*types.QueryUTXOResponse, error) {
	if req == nil {
		return nil, sdkerrors.ErrInvalidRequest.Wrap("request cannot be nil")
	}
	if len(req.Txid) != 2*types.BitcoinTxIDLength {
		return nil, sdkerrors.ErrInvalidRequest.Wrapf("txid must be %d hex characters, got %d", 2*types.BitcoinTxIDLength, len(req.Txid))
	}
	bigEndianTxid, err := hex.DecodeString(req.Txid)
	if err != nil {
		return nil, sdkerrors.ErrInvalidRequest.Wrapf("txid is not valid hex: %v", err)
	}
	wireTxid := reverseBytes(bigEndianTxid)

	utxo, err := qs.k.Utxoes.Get(ctx, types.UTXOKey(wireTxid, req.Vout))
	if err != nil {
		if errors.Is(err, collections.ErrNotFound) {
			return nil, sdkerrors.ErrKeyNotFound.Wrapf("UTXO not found: txid=%s vout=%d", req.Txid, req.Vout)
		}
		return nil, err
	}

	return &types.QueryUTXOResponse{Utxo: types.DisplayUTXO{
		Txid:           hex.EncodeToString(reverseBytes(utxo.Txid)),
		Vout:           utxo.Vout,
		Amount:         utxo.Amount,
		EntitledAmount: utxo.EntitledAmount,
		Address:        hex.EncodeToString(utxo.Address),
	}}, nil
}

// reverseBytes returns a reversed copy of b. Bitcoin txids are stored
// little-endian on the wire but displayed big-endian in user tools.
func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}
