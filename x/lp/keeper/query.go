package keeper

import (
	"context"
	"errors"

	"cosmossdk.io/collections"
	"cosmossdk.io/math"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	securedtypes "github.com/btcq-org/qbtc/x/secured/types"

	"github.com/btcq-org/qbtc/x/lp/types"
)

type queryServer struct {
	k *Keeper
}

func NewQueryServerImpl(k *Keeper) types.QueryServer {
	return &queryServer{k: k}
}

var _ types.QueryServer = (*queryServer)(nil)

func (q queryServer) Pool(ctx context.Context, _ *types.QueryPoolRequest) (*types.QueryPoolResponse, error) {
	p, err := q.k.Pool.Get(ctx)
	if err != nil {
		if errors.Is(err, collections.ErrNotFound) {
			return &types.QueryPoolResponse{}, nil
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &types.QueryPoolResponse{Pool: &p}, nil
}

func (q queryServer) LiquidityProvider(
	ctx context.Context, req *types.QueryLiquidityProviderRequest,
) (*types.QueryLiquidityProviderResponse, error) {
	if req == nil || req.NodeId == "" {
		return nil, status.Error(codes.InvalidArgument, "node_id required")
	}
	lp, err := q.k.LPs.Get(ctx, req.NodeId)
	if err != nil {
		if errors.Is(err, collections.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "lp not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &types.QueryLiquidityProviderResponse{Lp: &lp}, nil
}

func (q queryServer) Bond(ctx context.Context, req *types.QueryBondRequest) (*types.QueryBondResponse, error) {
	if req == nil || req.NodeId == "" {
		return nil, status.Error(codes.InvalidArgument, "node_id required")
	}
	b, err := q.k.Bonds.Get(ctx, req.NodeId)
	if err != nil {
		if errors.Is(err, collections.ErrNotFound) {
			return &types.QueryBondResponse{}, nil
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &types.QueryBondResponse{Bond: &b}, nil
}

func (q queryServer) PendingAdd(ctx context.Context, req *types.QueryPendingAddRequest) (*types.QueryPendingAddResponse, error) {
	if req == nil || req.Id == 0 {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	pa, err := q.k.PendingAdds.Get(ctx, req.Id)
	if err != nil {
		if errors.Is(err, collections.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "pending add not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &types.QueryPendingAddResponse{Pending: &pa}, nil
}

func (q queryServer) PendingAdds(ctx context.Context, _ *types.QueryPendingAddsRequest) (*types.QueryPendingAddsResponse, error) {
	resp := &types.QueryPendingAddsResponse{}
	if err := q.k.PendingAdds.Walk(ctx, nil, func(_ uint64, pa types.PendingAdd) (bool, error) {
		resp.Pending = append(resp.Pending, &pa)
		return false, nil
	}); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return resp, nil
}

func (q queryServer) QuoteSwap(ctx context.Context, req *types.QueryQuoteSwapRequest) (*types.QueryQuoteSwapResponse, error) {
	if req == nil || req.Amount == "" {
		return nil, status.Error(codes.InvalidArgument, "amount required")
	}
	amount, err := math.ParseUint(req.Amount)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "amount: "+err.Error())
	}
	pool, err := q.k.Pool.Get(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	var inBal, outBal math.Uint
	switch req.SourceDenom {
	case types.DenomQbtc:
		inBal, outBal = pool.BalanceQbtc, pool.BalanceSbtc
	case securedtypes.DenomSecuredBTC:
		inBal, outBal = pool.BalanceSbtc, pool.BalanceQbtc
	default:
		return nil, status.Error(codes.InvalidArgument, "source_denom must be qbtc or sbtc")
	}

	out, err := types.CalcSwapOutput(amount, inBal, outBal)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	slip := types.CalcSlipBps(amount, inBal)
	return &types.QueryQuoteSwapResponse{
		OutAmount: out.String(),
		SlipBps:   uint32(slip.Uint64()),
	}, nil
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
