package keeper_test

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/query"
	"github.com/stretchr/testify/require"

	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// createValoperAddress creates a validator operator address from the given bytes
func createValoperAddress(bytes []byte) string {
	accAddr := sdk.AccAddress(bytes)
	valAddr := sdk.ValAddress(accAddr)
	return valAddr.String()
}

func TestQueryNodePeerAddress(t *testing.T) {
	f := initFixture(t)
	queryClient := keeper.NewQueryServerImpl(f.keeper)

	// Create multiple qbtc valoper addresses with peer addresses
	testData := map[string]string{
		createValoperAddress([]byte("node1")): "node1@192.168.1.1:9999",
		createValoperAddress([]byte("node2")): "node2@192.168.1.2:9999",
		createValoperAddress([]byte("node3")): "node3@192.168.1.3:9999",
		createValoperAddress([]byte("node4")): "node4@10.0.0.1:9999",
		createValoperAddress([]byte("node5")): "node5@10.0.0.2:9999",
	}

	// Set all node peer addresses
	for address, peerAddress := range testData {
		err := f.keeper.NodePeerAddresses.Set(f.ctx, address, peerAddress)
		require.NoError(t, err)
	}

	// Test single query for each address
	for address, expectedPeerAddress := range testData {
		resp, err := queryClient.NodePeerAddress(f.ctx, &types.QueryNodePeerAddressRequest{Address: address})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, address, resp.Address)
		require.Equal(t, expectedPeerAddress, resp.PeerAddress)
	}

	// Test query for non-existent address
	nonExistentAddr := createValoperAddress([]byte("nonexistent"))
	_, err := queryClient.NodePeerAddress(f.ctx, &types.QueryNodePeerAddressRequest{Address: nonExistentAddr})
	require.Error(t, err)

	// Test all node peer addresses query
	allResp, err := queryClient.AllNodePeerAddresses(f.ctx, &types.QueryAllNodePeerAddressesRequest{})
	require.NoError(t, err)
	require.NotNil(t, allResp)
	require.Len(t, allResp.NodePeerAddresses, len(testData))

	// Verify all returned node peer addresses match what we set
	returnedMap := make(map[string]string)
	for _, nodePeerAddress := range allResp.NodePeerAddresses {
		returnedMap[nodePeerAddress.Address] = nodePeerAddress.PeerAddress
	}

	for address, expectedPeerAddress := range testData {
		actualPeerAddress, exists := returnedMap[address]
		require.True(t, exists, "Address %s should be in the response", address)
		require.Equal(t, expectedPeerAddress, actualPeerAddress, "Peer address for address %s should match", address)
	}

	// Test paginated query with limit 2
	pageReq := &query.PageRequest{
		Limit: 2,
	}
	allNodes := make(map[string]string)
	pageCount := 0
	maxPages := 10 // safety limit

	for pageReq != nil && pageCount < maxPages {
		paginatedResp, err := queryClient.AllNodePeerAddresses(f.ctx, &types.QueryAllNodePeerAddressesRequest{
			Pagination: pageReq,
		})
		require.NoError(t, err)
		require.NotNil(t, paginatedResp)
		require.LessOrEqual(t, len(paginatedResp.NodePeerAddresses), 2, "Page should have at most 2 items")

		// Collect all nodes from this page
		for _, nodePeerAddress := range paginatedResp.NodePeerAddresses {
			allNodes[nodePeerAddress.Address] = nodePeerAddress.PeerAddress
		}

		// Check if there's a next page
		if paginatedResp.Pagination != nil && len(paginatedResp.Pagination.NextKey) > 0 {
			pageReq = &query.PageRequest{
				Key:   paginatedResp.Pagination.NextKey,
				Limit: 2,
			}
		} else {
			pageReq = nil
		}
		pageCount++
	}

	// Verify we got all 5 nodes through pagination
	require.Len(t, allNodes, len(testData), "Should have collected all nodes through pagination")
	require.Greater(t, pageCount, 1, "Should have required multiple pages")

	// Verify all returned node peer addresses match what we set
	for address, expectedPeerAddress := range testData {
		actualPeerAddress, exists := allNodes[address]
		require.True(t, exists, "Address %s should be in the paginated response", address)
		require.Equal(t, expectedPeerAddress, actualPeerAddress, "Peer address for address %s should match", address)
	}
}
