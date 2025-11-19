package keeper

import (
	"context"

	"github.com/btcq-org/qbtc/x/qbtc/types"
	se "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/types/query"
)

func (qs queryServer) NodePeerAddress(ctx context.Context, req *types.QueryNodePeerAddressRequest) (*types.QueryNodePeerAddressResponse, error) {
	if req.Address == "" {
		return nil, se.ErrInvalidAddress.Wrap("address is required")
	}
	peerAddress, err := qs.k.NodePeerAddresses.Get(ctx, req.Address)
	if err != nil {
		return nil, err
	}
	return &types.QueryNodePeerAddressResponse{Address: req.Address, PeerAddress: peerAddress}, nil
}

func (qs queryServer) AllNodePeerAddresses(ctx context.Context, req *types.QueryAllNodePeerAddressesRequest) (*types.QueryAllNodePeerAddressesResponse, error) {
	nodePeerAddresses, pageRes, err := query.CollectionPaginate(ctx, qs.k.NodePeerAddresses, req.Pagination, func(key string, value string) (*types.QueryNodePeerAddressResponse, error) {
		return &types.QueryNodePeerAddressResponse{Address: key, PeerAddress: value}, nil
	})

	if err != nil {
		return nil, err
	}
	return &types.QueryAllNodePeerAddressesResponse{NodePeerAddresses: nodePeerAddresses, Pagination: pageRes}, nil
}
