package keeper

import (
	"context"

	"github.com/btcq-org/btcq/x/btcq/types"
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

func (q queryServer) Node(ctx context.Context, request *types.QueryNodeRequest) (*types.QueryNodeResponse, error) {

	//TODO implement me
	panic("implement me")
}

func (q queryServer) Nodes(ctx context.Context, request *types.QueryNodesRequest) (*types.QueryNodesResponse, error) {
	//TODO implement me
	panic("implement me")
}
