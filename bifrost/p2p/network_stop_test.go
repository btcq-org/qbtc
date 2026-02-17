package p2p

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	qtypes "github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/cosmos/cosmos-sdk/types"
	"github.com/libp2p/go-libp2p/core/peer"
	mocknet "github.com/libp2p/go-libp2p/p2p/net/mock"
	"github.com/stretchr/testify/require"
)

type mockQBTCNode struct {
	bootstrapPeers []peer.AddrInfo
}

func (m mockQBTCNode) GetBootstrapPeers(ctx context.Context) ([]peer.AddrInfo, error) {
	return m.bootstrapPeers, nil
}

func (m mockQBTCNode) VerifyAttestation(ctx context.Context, block qtypes.BlockGossip) error {
	return nil
}

func (m mockQBTCNode) CheckAttestationsSuperMajority(ctx context.Context, msg *qtypes.MsgBtcBlock) error {
	return nil
}

func (m mockQBTCNode) GetLatestBtcBlockHeight(ctx context.Context) (uint64, error) {
	return 0, nil
}

func (m mockQBTCNode) IsActiveValidator(ctx context.Context, consAddr types.ConsAddress) (bool, error) {
	return true, nil
}

func (m mockQBTCNode) IsSyncing(ctx context.Context) (bool, error) {
	return false, nil
}

func TestStopWaitsForInFlightValidatorConnect(t *testing.T) {
	mn := mocknet.New()
	h, err := mn.GenPeer()
	require.NoError(t, err)

	validator1, err := peer.Decode("12D3KooWJ7pcnYjFQm6zAN2nKpNQ6qVZg6zkRgZNpmjQe7YQDdyC")
	require.NoError(t, err)
	validator2, err := peer.Decode("12D3KooWF3BzN3s6qVwBEmc6k9RdtqvYXvyfZ7Z84qxdjQbaVkjj")
	require.NoError(t, err)
	validator3, err := peer.Decode("12D3KooWQ5y6X4g4zvN8iV4tFxR8M9u9xUtrJ9Q4d2Q9zvQ1n4hN")
	require.NoError(t, err)
	validator4, err := peer.Decode("12D3KooWDV8prY2Rz2u8sY4x7t7g8W6x2K1XyRkz2ZzM9iQ3o2nL")
	require.NoError(t, err)
	validator5, err := peer.Decode("12D3KooWJ2c9xq5d3Qf8qR6kP2b3m4n5v6x7y8z9a1b2c3d4e5fG")
	require.NoError(t, err)

	bootstrapPeers := []peer.AddrInfo{
		{ID: validator1},
		{ID: validator2},
		{ID: validator3},
		{ID: validator4},
		{ID: validator5},
	}

	n := &Network{
		h:              h,
		qBTCNode:       mockQBTCNode{bootstrapPeers: bootstrapPeers},
		validatorPeers: map[peer.ID]peer.AddrInfo{validator1: {ID: validator1}},
		stopChan:       make(chan struct{}),
	}

	unblockConnect := make(chan struct{})
	var connectCalls atomic.Int32
	n.connectPeer = func(p peer.AddrInfo) {
		connectCalls.Add(1)
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			<-unblockConnect
		}()
	}

	n.refreshValidatorPeers(context.Background())
	require.Equal(t, int32(4), connectCalls.Load(), "should connect only newly discovered validators")

	stopDone := make(chan error, 1)
	go func() {
		stopDone <- n.Stop()
	}()

	select {
	case err := <-stopDone:
		t.Fatalf("Stop returned before connect goroutine completed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(unblockConnect)

	select {
	case err := <-stopDone:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return after connect goroutine completed")
	}
}
