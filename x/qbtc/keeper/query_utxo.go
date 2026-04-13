package keeper

import (
	"context"

	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/types/query"
)

func (qs queryServer) UTXOsByAddress(ctx context.Context, req *types.QueryUTXOsByAddressRequest) (*types.QueryUTXOsByAddressResponse, error) {
	if req.BtcAddress == "" {
		return nil, sdkerrors.ErrInvalidRequest.Wrap("btc_address is required")
	}

	// Use the ByAddress secondary index to get primary keys, then fetch UTXOs.
	iter, err := qs.k.Utxoes.Indexes.ByAddress.MatchExact(ctx, req.BtcAddress)
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	pks, err := iter.PrimaryKeys()
	if err != nil {
		return nil, err
	}

	// Apply pagination over the primary keys.
	limit := uint64(query.DefaultLimit)
	offset := uint64(0)
	if req.Pagination != nil {
		if req.Pagination.Limit > 0 {
			limit = req.Pagination.Limit
		}
		offset = req.Pagination.Offset
	}

	total := uint64(len(pks))
	end := offset + limit
	if end > total {
		end = total
	}
	if offset > total {
		offset = total
	}

	var utxos []types.UTXO
	for _, pk := range pks[offset:end] {
		utxo, err := qs.k.Utxoes.Get(ctx, pk)
		if err != nil {
			return nil, err
		}
		utxos = append(utxos, utxo)
	}

	return &types.QueryUTXOsByAddressResponse{
		Utxos: utxos,
		Pagination: &query.PageResponse{
			Total: total,
		},
	}, nil
}
