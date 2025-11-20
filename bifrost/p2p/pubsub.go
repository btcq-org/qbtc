package p2p

import (
	"context"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/protocol"
)

func pubSub(ctx context.Context, host host.Host) (*pubsub.PubSub, error) {
	options := []pubsub.Option{
		pubsub.WithGossipSubProtocols([]protocol.ID{pubsub.GossipSubID_v11}, pubsub.GossipSubDefaultFeatures),
	}
	pubsub, err := pubsub.NewGossipSub(
		ctx,
		host,
		options...,
	)
	if err != nil {
		return nil, err
	}
	return pubsub, nil
}
