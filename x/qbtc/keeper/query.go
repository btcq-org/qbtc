package keeper

import (
	"context"
	"errors"

	"cosmossdk.io/collections"
	"github.com/btcq-org/qbtc/constants"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ types.QueryServer = queryServer{}

// NewQueryServerImpl returns an implementation of the QueryServer interface
// for the provided Keeper.
func NewQueryServerImpl(k Keeper) types.QueryServer {
	return queryServer{k}
}

type queryServer struct {
	k Keeper
}

// AllParams implements types.QueryServer.
func (qs queryServer) AllParams(ctx context.Context, req *types.QueryAllParamsRequest) (*types.QueryAllParamsResponse, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	params := []*types.Param{}
	for key, value := range constants.DefaultValues {
		params = append(params, &types.Param{
			Key:   key.String(),
			Value: value,
		})
	}
	for _, p := range params {
		overriddenValue, err := qs.k.ConstOverrides.Get(sdkCtx, p.Key)
		if err != nil {
			if errors.Is(err, collections.ErrNotFound) {
				continue
			}
			sdkCtx.Logger().Error("failed to get constant override", "key", p.Key, "error", err)
		}
		p.Value = overriddenValue
	}
	return &types.QueryAllParamsResponse{Params: params}, nil
}

// Params implements types.QueryServer.
func (qs queryServer) Params(ctx context.Context, req *types.QueryParamsRequest) (*types.QueryParamsResponse, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	if req.Key == "" {
		return nil, sdkerrors.ErrUnknownRequest.Wrap("parameter key cannot be empty")
	}
	value, err := qs.k.ConstOverrides.Get(sdkCtx, req.Key)
	if err != nil {
		return nil, err
	}
	return &types.QueryParamsResponse{Param: &types.Param{Key: req.Key, Value: value}}, nil
}
