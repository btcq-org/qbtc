package p2p

import (
	"context"
	"fmt"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

// PubSub creates a new pubsub instance for the p2p network
func PubSub(ctx context.Context, host host.Host, directPeers []peer.AddrInfo) (*pubsub.PubSub, error) {
	options := []pubsub.Option{
		pubsub.WithGossipSubProtocols([]protocol.ID{pubsub.GossipSubID_v13}, pubsub.GossipSubDefaultFeatures),
		pubsub.WithDirectPeers(directPeers),
	}
	pubsub, err := pubsub.NewGossipSub(
		ctx,
		host,
		options...,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to start gossip pub sub,err: %w", err)
	}
	return pubsub, nil
}
