package keeper

import (
	"context"
	"errors"
	"fmt"

	"cosmossdk.io/collections"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

func (qs queryServer) UTXO(ctx context.Context, req *types.QueryUTXORequest) (*types.QueryUTXOResponse, error) {
	if req == nil {
		return nil, sdkerrors.ErrInvalidRequest.Wrap("request cannot be nil")
	}
	if req.Txid == "" {
		return nil, sdkerrors.ErrInvalidRequest.Wrap("txid is required")
	}

	key := fmt.Sprintf("%s-%d", req.Txid, req.Vout)
	utxo, err := qs.k.Utxoes.Get(ctx, key)
	if err != nil {
		if errors.Is(err, collections.ErrNotFound) {
			return nil, sdkerrors.ErrKeyNotFound.Wrapf("UTXO not found: txid=%s vout=%d", req.Txid, req.Vout)
		}
		return nil, err
	}

	return &types.QueryUTXOResponse{Utxo: utxo}, nil
}
