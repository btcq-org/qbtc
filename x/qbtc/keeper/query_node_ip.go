package keeper

import (
	"context"

	"github.com/btcq-org/qbtc/x/qbtc/types"
	se "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/types/query"
)

func (qs queryServer) NodeIP(ctx context.Context, req *types.QueryNodeIPRequest) (*types.QueryNodeIPResponse, error) {
	if req.Address == "" {
		return nil, se.ErrInvalidAddress.Wrap("address is required")
	}
	ip, err := qs.k.NodeIPs.Get(ctx, req.Address)
	if err != nil {
		return nil, err
	}
	return &types.QueryNodeIPResponse{Address: req.Address, IP: ip}, nil
}

func (qs queryServer) AllNodeIPs(ctx context.Context, req *types.QueryAllNodeIPsRequest) (*types.QueryAllNodeIPsResponse, error) {
	nodeIPs, pageRes, err := query.CollectionPaginate(ctx, qs.k.NodeIPs, req.Pagination, func(key string, value string) (*types.QueryNodeIPResponse, error) {
		return &types.QueryNodeIPResponse{Address: key, IP: value}, nil
	})

	if err != nil {
		return nil, err
	}
	return &types.QueryAllNodeIPsResponse{NodeIPs: nodeIPs, Pagination: pageRes}, nil
}
