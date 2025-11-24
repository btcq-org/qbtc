package p2p

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/gogo/protobuf/proto"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/syndtr/goleveldb/leveldb"
)

const topic = "bifrost-bitcoin-block-gossip-sub"
const DefaultTimeout = 10 * time.Second // in seconds
type PubSubService struct {
	pubsub   *pubsub.PubSub
	host     host.Host
	topic    *pubsub.Topic
	logger   zerolog.Logger
	stopchan chan struct{}
	wg       *sync.WaitGroup
	db       *leveldb.DB
	chanMsg  chan types.MsgBtcBlock
}

// NewPubSubService creates a new PubSubService instance
func NewPubSubService(host host.Host, directPeers []peer.AddrInfo, db *leveldb.DB) (*PubSubService, error) {
	if db == nil {
		return nil, fmt.Errorf("leveldb instance is nil")
	}
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()
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
	topic, err := pubsub.Join(topic)
	if err != nil {
		return nil, fmt.Errorf("fail to join topic, err: %w", err)
	}
	return &PubSubService{
		pubsub:   pubsub,
		host:     host,
		topic:    topic,
		logger:   log.With().Str("module", "pubsub_service").Logger(),
		stopchan: make(chan struct{}),
		wg:       &sync.WaitGroup{},
		db:       db,
		chanMsg:  make(chan types.MsgBtcBlock),
	}, nil
}

// GetChanMsg returns the channel for MsgBtcBlock messages
func (p *PubSubService) GetChanMsg() chan types.MsgBtcBlock {
	return p.chanMsg
}

// GetPubSub returns the underlying PubSub instance
func (p *PubSubService) GetPubSub() *pubsub.PubSub {
	return p.pubsub
}

// GetTopic returns the PubSub topic
func (p *PubSubService) GetTopic() *pubsub.Topic {
	return p.topic
}

// Start starts the PubSubService to listen for incoming messages
func (p *PubSubService) Start() error {
	if p.topic == nil {
		return fmt.Errorf("pubsub topic is nil")
	}
	sub, err := p.topic.Subscribe()
	if err != nil {
		return fmt.Errorf("failed to subscribe to topic: %w", err)
	}
	p.wg.Add(1)
	go p.processMessages(sub)
	return nil
}

func (p *PubSubService) processMessages(sub *pubsub.Subscription) {
	defer p.wg.Done()
	for {
		select {
		case <-p.stopchan:
			p.logger.Info().Msg("stopping pubsub message processing")
			return
		default:
			p.handleMessage(sub)
		}
	}
}

func (p *PubSubService) handleMessage(sub *pubsub.Subscription) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()
	msg, err := sub.Next(ctx)
	if err != nil {
		p.logger.Error().Err(err).Msg("failed to get next message from subscription")
		return
	}
	// Process the message
	p.logger.Info().Msgf("received message from %s: %s", msg.GetFrom(), string(msg.GetData()))

	var block types.BlockGossip
	if err := proto.Unmarshal(msg.GetData(), &block); err != nil {
		p.logger.Error().Err(err).Msg("failed to unmarshal block gossip message")
		return
	}
	p.logger.Info().Str("from", msg.GetFrom().String()).Msgf("received block gossip message: %s", block.GetKey())
	if err := p.aggregateAttestations(block); err != nil {
		p.logger.Error().Err(err).Msg("failed to aggregate attestations")
		return
	}
	p.logger.Info().Str("from", msg.GetFrom().String()).Msgf("successfully processed block gossip message: %s", block.GetKey())

}

func (p *PubSubService) aggregateAttestations(block types.BlockGossip) error {
	if p.db == nil {
		return fmt.Errorf("leveldb instance is nil")
	}
	key := block.GetKey()
	existingContent, err := p.db.Get([]byte(key), nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			msg := types.MsgBtcBlock{
				Height:       block.Height,
				Hash:         block.Hash,
				BlockContent: block.BlockContent,
				Attestations: []*types.Attestation{block.Attestation},
			}
			return p.saveMsgBtcBlock(msg)
		}
		return fmt.Errorf("failed to get existing attestations from db: %w", err)
	}
	var msgBlock types.MsgBtcBlock
	if err := proto.Unmarshal(existingContent, &msgBlock); err != nil {
		return fmt.Errorf("failed to unmarshal existing block gossip message: %w", err)
	}
	if bytes.Equal(msgBlock.BlockContent, block.BlockContent) {
		msgBlock.Attestations = append(msgBlock.Attestations, block.Attestation)
	}
	return p.saveMsgBtcBlock(msgBlock)
}

func (p *PubSubService) saveMsgBtcBlock(msgBlock types.MsgBtcBlock) error {
	if p.db == nil {
		return fmt.Errorf("leveldb instance is nil")
	}
	key := fmt.Sprintf("%s-%d", msgBlock.Hash, msgBlock.Height)
	content, err := proto.Marshal(&msgBlock)
	if err != nil {
		return fmt.Errorf("failed to marshal MsgBtcBlock: %w", err)
	}
	if err := p.db.Put([]byte(key), content, nil); err != nil {
		return fmt.Errorf("failed to put MsgBtcBlock to db: %w", err)
	}
	return nil
}

// Publish publishes a message to the pubsub topic
func (p *PubSubService) Publish(block types.BlockGossip) error {
	if p.topic == nil {
		return fmt.Errorf("pubsub topic is nil")
	}
	msg, err := proto.Marshal(&block)
	if err != nil {
		return fmt.Errorf("failed to marshal block gossip message: %w", err)
	}
	if err := p.topic.Publish(context.Background(), msg); err != nil {
		return fmt.Errorf("failed to publish message: %w", err)
	}
	return nil
}

func (p *PubSubService) Stop() error {
	close(p.stopchan)
	p.wg.Wait()
	if p.topic != nil {
		if err := p.topic.Close(); err != nil {
			p.logger.Error().Err(err).Msg("failed to close pubsub topic")
		}
	}
	return nil
}
