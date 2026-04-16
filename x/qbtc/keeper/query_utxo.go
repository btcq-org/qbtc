package keeper

import (
	"context"

	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/types/query"
)

func (qs queryServer) UTXOsByAddress(ctx context.Context, req *types.QueryUTXOsByAddressRequest) (*types.QueryUTXOsByAddressResponse, error) {
	if req == nil {
		return nil, sdkerrors.ErrInvalidRequest.Wrap("request cannot be nil")
	}

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

	// Resolve primary keys to UTXOs, applying the claimable filter if set.
	matched := make([]types.UTXO, 0, len(pks))
	for _, pk := range pks {
		utxo, err := qs.k.Utxoes.Get(ctx, pk)
		if err != nil {
			return nil, err
		}
		if req.Claimable && utxo.EntitledAmount == 0 {
			continue
		}
		matched = append(matched, utxo)
	}

	// Apply pagination over the filtered list.
	limit := uint64(query.DefaultLimit)
	offset := uint64(0)
	if req.Pagination != nil {
		if req.Pagination.Limit > 0 {
			limit = req.Pagination.Limit
		}
		offset = req.Pagination.Offset
	}

	total := uint64(len(matched))
	if offset > total {
		offset = total
	}
	end := offset + limit
	if limit > total-offset {
		end = total
	}

	utxos := matched[offset:end]

	return &types.QueryUTXOsByAddressResponse{
		Utxos: utxos,
		Pagination: &query.PageResponse{
			Total: total,
		},
	}, nil
}
