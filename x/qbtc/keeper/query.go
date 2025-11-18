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

// AllParams returns all parameters in the qbtc module.
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

// Params returns the value of a specific parameter in the qbtc module.
func (qs queryServer) Params(ctx context.Context, req *types.QueryParamsRequest) (*types.QueryParamsResponse, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	if req.Key == "" {
		return nil, sdkerrors.ErrUnknownRequest.Wrap("parameter key cannot be empty")
	}
	value, err := qs.k.ConstOverrides.Get(sdkCtx, req.Key)
	if err != nil {
		if errors.Is(err, collections.ErrNotFound) {
			constName, ok := constants.FromString(req.Key)
			if !ok {
				return nil, sdkerrors.ErrUnknownRequest.Wrapf("unknown parameter key: %s", req.Key)
			}
			defaultValue, exists := constants.DefaultValues[constName]
			if !exists {
				return nil, sdkerrors.ErrUnknownRequest.Wrapf("unknown parameter key: %s", req.Key)
			}
			value = defaultValue
		} else {
			return nil, err
		}
	}
	return &types.QueryParamsResponse{Param: &types.Param{Key: req.Key, Value: value}}, nil
}
