package keeper

import (
	"context"

	"github.com/btcq-org/qbtc/x/qbtc/types"
)

func (qs queryServer) NodeIP(ctx context.Context, req *types.QueryNodeIPRequest) (*types.QueryNodeIPResponse, error) {
	ip, err := qs.k.NodeIPs.Get(ctx, req.Address)
	if err != nil {
		return nil, err
	}
	return &types.QueryNodeIPResponse{Address: req.Address, IP: ip}, nil
}

func (qs queryServer) AllNodeIPs(ctx context.Context, req *types.QueryAllNodeIPsRequest) (*types.QueryAllNodeIPsResponse, error) {
	nodeIPs := make([]*types.QueryNodeIPResponse, 0)
	err := qs.k.NodeIPs.Walk(ctx, nil, func(key string, value string) (stop bool, err error) {
		nodeIPs = append(nodeIPs, &types.QueryNodeIPResponse{Address: key, IP: value})
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	return &types.QueryAllNodeIPsResponse{NodeIPs: nodeIPs}, nil
}
