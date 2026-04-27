package keeper

import (
	"context"
	"errors"

	"cosmossdk.io/collections"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/btcq-org/qbtc/x/secured/types"
)

type queryServer struct {
	k *Keeper
}

func NewQueryServerImpl(k *Keeper) types.QueryServer {
	return &queryServer{k: k}
}

var _ types.QueryServer = (*queryServer)(nil)

func (q queryServer) Vault(ctx context.Context, _ *types.QueryVaultRequest) (*types.QueryVaultResponse, error) {
	v, err := q.k.Vault.Get(ctx)
	if err != nil {
		if errors.Is(err, collections.ErrNotFound) {
			return &types.QueryVaultResponse{}, nil
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &types.QueryVaultResponse{Vault: &v}, nil
}

func (q queryServer) TxOut(ctx context.Context, req *types.QueryTxOutRequest) (*types.QueryTxOutResponse, error) {
	if req == nil || req.Id == 0 {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	item, err := q.k.TxOutQueue.Get(ctx, req.Id)
	if err != nil {
		if errors.Is(err, collections.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "tx out not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &types.QueryTxOutResponse{TxOut: &item}, nil
}

func (q queryServer) TxOutQueue(ctx context.Context, _ *types.QueryTxOutQueueRequest) (*types.QueryTxOutQueueResponse, error) {
	resp := &types.QueryTxOutQueueResponse{}
	if err := q.k.TxOutQueue.Walk(ctx, nil, func(_ uint64, item types.TxOutItem) (bool, error) {
		resp.Items = append(resp.Items, &item)
		return false, nil
	}); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return resp, nil
}

func (q queryServer) Param(ctx context.Context, req *types.QueryParamRequest) (*types.QueryParamResponse, error) {
	if req == nil || req.Key == "" {
		return nil, status.Error(codes.InvalidArgument, "key required")
	}
	if !types.IsKnownParam(req.Key) {
		return nil, status.Error(codes.NotFound, "unknown parameter key")
	}
	return &types.QueryParamResponse{Param: &types.Param{
		Key:   req.Key,
		Value: q.k.GetParam(ctx, req.Key),
	}}, nil
}

func (q queryServer) AllParams(ctx context.Context, _ *types.QueryAllParamsRequest) (*types.QueryAllParamsResponse, error) {
	resp := &types.QueryAllParamsResponse{}
	for key := range types.DefaultParams() {
		resp.Params = append(resp.Params, &types.Param{
			Key:   key,
			Value: q.k.GetParam(ctx, key),
		})
	}
	return resp, nil
}
