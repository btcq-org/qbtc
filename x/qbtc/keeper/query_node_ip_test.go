package keeper_test

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
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

func TestQueryNodeIP(t *testing.T) {
	f := initFixture(t)
	queryClient := keeper.NewQueryServerImpl(f.keeper)

	// Create multiple qbtc valoper addresses with IPs
	testData := map[string]string{
		createValoperAddress([]byte("node1")): "192.168.1.1",
		createValoperAddress([]byte("node2")): "192.168.1.2",
		createValoperAddress([]byte("node3")): "192.168.1.3",
		createValoperAddress([]byte("node4")): "10.0.0.1",
		createValoperAddress([]byte("node5")): "10.0.0.2",
	}

	// Set all node IPs
	for address, ip := range testData {
		_ = f.keeper.NodeIPs.Set(f.ctx, address, ip)
	}

	// Test single query for each address
	for address, expectedIP := range testData {
		resp, err := queryClient.NodeIP(f.ctx, &types.QueryNodeIPRequest{Address: address})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, address, resp.Address)
		require.Equal(t, expectedIP, resp.IP)
	}

	// Test query for non-existent address
	nonExistentAddr := createValoperAddress([]byte("nonexistent"))
	_, err := queryClient.NodeIP(f.ctx, &types.QueryNodeIPRequest{Address: nonExistentAddr})
	require.Error(t, err)

	// Test all node IPs query
	allResp, err := queryClient.AllNodeIPs(f.ctx, &types.QueryAllNodeIPsRequest{})
	require.NoError(t, err)
	require.NotNil(t, allResp)
	require.Len(t, allResp.NodeIPs, len(testData))

	// Verify all returned node IPs match what we set
	returnedMap := make(map[string]string)
	for _, nodeIP := range allResp.NodeIPs {
		returnedMap[nodeIP.Address] = nodeIP.IP
	}

	for address, expectedIP := range testData {
		actualIP, exists := returnedMap[address]
		require.True(t, exists, "Address %s should be in the response", address)
		require.Equal(t, expectedIP, actualIP, "IP for address %s should match", address)
	}
}
