package p2p

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/btcq-org/qbtc/bifrost/config"
	"github.com/btcq-org/qbtc/bifrost/keystore"
	"github.com/btcq-org/qbtc/bifrost/metrics"
	qclient "github.com/btcq-org/qbtc/bifrost/qclient"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
	quic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	maddr "github.com/multiformats/go-multiaddr"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	validatorTag             = "validator"
	validatorTagValue        = 100
	validatorRefreshInterval = 60 * time.Second
	bootstrapConnectTimeout  = 10 * time.Second
)

// Network is the p2p network
type Network struct {
	config *config.P2PConfig

	listenAddr       maddr.Multiaddr
	listenAddrQUIC   maddr.Multiaddr
	externalAddr     maddr.Multiaddr
	externalAddrQUIC maddr.Multiaddr
	// p2p host
	h host.Host

	qBTCNode qclient.QBTCNode
	localDHT *dht.IpfsDHT
	logger   zerolog.Logger
	metrics  *metrics.Metrics

	validatorPeersMu sync.RWMutex
	validatorPeers   map[peer.ID]peer.AddrInfo
	stopChan         chan struct{}
	wg               sync.WaitGroup
	connectPeer      func(peer.AddrInfo)
}

func NewNetwork(config *config.P2PConfig, qBTCNode qclient.QBTCNode, metrics *metrics.Metrics) (*Network, error) {
	if config == nil {
		return nil, ErrInvalidConfig
	}
	if qBTCNode == nil {
		return nil, ErrInvalidQBTCNodeClient
	}
	if config.Port < 1 || config.Port > 65535 {
		return nil, fmt.Errorf("invalid port: %d", config.Port)
	}

	listenAddr, err := maddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", config.Port))
	if err != nil {
		return nil, fmt.Errorf("failed to create listen address: %w", err)
	}
	listenAddrQUIC, err := maddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic", config.Port))
	if err != nil {
		return nil, fmt.Errorf("failed to create QUIC listen address: %w", err)
	}

	n := &Network{
		config:         config,
		listenAddr:     listenAddr,
		listenAddrQUIC: listenAddrQUIC,
		qBTCNode:       qBTCNode,
		localDHT:       nil,
		logger:         log.With().Str("module", "p2p").Logger(),
		metrics:        metrics,
	}
	n.connectPeer = n.connectValidatorPeer

	if config.ExternalIP != "" {
		if net.ParseIP(config.ExternalIP) == nil {
			return nil, fmt.Errorf("invalid external IP: %s", config.ExternalIP)
		}
		n.externalAddr, err = maddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d", config.ExternalIP, config.Port))
		if err != nil {
			return nil, fmt.Errorf("failed to create external address: %w", err)
		}
		n.externalAddrQUIC, err = maddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/udp/%d/quic", config.ExternalIP, config.Port))
		if err != nil {
			return nil, fmt.Errorf("failed to create QUIC external address: %w", err)
		}
	}
	return n, nil
}

// addressFactory is a function that returns the external address if it is set, otherwise returns the input addresses
func (n *Network) addressFactory(addrs []maddr.Multiaddr) []maddr.Multiaddr {
	if n.externalAddr != nil {
		// Return both TCP and QUIC external addresses
		return []maddr.Multiaddr{n.externalAddr, n.externalAddrQUIC}
	}
	return addrs
}

// ConnectedPeers returns the list of connected peers
func (n *Network) ConnectedPeers() []peer.AddrInfo {
	peers := n.h.Peerstore().Peers()
	addrInfos := make([]peer.AddrInfo, 0, len(peers))
	for _, peer := range peers {
		if peer == n.h.ID() {
			continue
		}
		addrInfos = append(addrInfos, n.h.Peerstore().PeerInfo(peer))
	}
	return addrInfos
}

// Start starts the p2p network
func (n *Network) Start(ctx context.Context, key *keystore.PrivKey) error {
	if key == nil {
		return ErrInvalidKey
	}
	if n.h != nil {
		return ErrNetworkAlreadyStarted
	}
	privKey, err := crypto.UnmarshalPrivateKey(key.Body)
	if err != nil {
		return err
	}
	cm, err := connmgr.NewConnManager(
		40,  // low watermark
		100, // high watermark
		connmgr.WithGracePeriod(time.Minute),
	)
	if err != nil {
		return fmt.Errorf("failed to create connection manager: %w", err)
	}
	opts := []libp2p.Option{
		libp2p.ListenAddrs(n.listenAddr, n.listenAddrQUIC),
		libp2p.ChainOptions(
			libp2p.Transport(tcp.NewTCPTransport),
			libp2p.Transport(quic.NewTransport),
		),
		// Add the private key to the libp2p options
		libp2p.Identity(privKey),
		// address factory
		libp2p.AddrsFactory(n.addressFactory),
		libp2p.ConnectionManager(cm),
	}
	host, err := libp2p.New(opts...)
	if err != nil {
		return err
	}
	n.h = host
	n.validatorPeers = make(map[peer.ID]peer.AddrInfo)
	n.stopChan = make(chan struct{})

	dht, err := dht.New(ctx, n.h,
		dht.QueryFilter(dht.PublicQueryFilter),
		dht.RoutingTableFilter(dht.PublicRoutingTableFilter),
	)
	if err != nil {
		return fmt.Errorf("failed to start DHT network,err: %w", err)
	}
	n.logger.Info().Msg("DHT network started")
	err = dht.Bootstrap(ctx)
	if err != nil {
		return fmt.Errorf("failed to bootstrap DHT network,err: %w", err)
	}
	n.logger.Info().Msg("DHT network bootstrapped")
	n.localDHT = dht

	// Print local peer addresses for other nodes to connect
	n.printLocalPeerAddresses()

	bootstrapPeers, err := n.waitForQBTCNodeReady(ctx)
	if err != nil {
		return fmt.Errorf("failed to get bootstrap peers,err: %w", err)
	}
	if len(bootstrapPeers) == 0 {
		n.logger.Warn().Msg("no bootstrap peers found")
	}
	err = n.BootstrapInitialPeers(bootstrapPeers)
	if err != nil {
		return fmt.Errorf("failed to bootstrap initial peers,err: %w", err)
	}
	n.logger.Info().Msg("bootstrap initial peers")

	n.wg.Add(1)
	go n.startValidatorPeerRefresh(ctx)

	return nil
}

// printLocalPeerAddresses prints the local node's P2P addresses that other nodes can use to connect
func (n *Network) printLocalPeerAddresses() {
	peerID := n.h.ID()

	n.logger.Info().Str("peer_id", peerID.String()).Msg("Local P2P node started")

	if n.config.ExternalIP != "" {
		n.logger.Info().Msgf("Using external IP: %s@%s:%d", peerID.String(), n.config.ExternalIP, n.config.Port)
	} else {
		n.logger.Info().Msgf("No external IP configured; using local addresses %s@0.0.0.0:%d", peerID.String(), n.config.Port)
	}

}

func (n *Network) waitForQBTCNodeReady(ctx context.Context) (bootstrapPeers []peer.AddrInfo, err error) {
	for i := range 100 {
		bootstrapPeers, err = n.qBTCNode.GetBootstrapPeers(ctx)
		if err != nil {
			n.logger.Err(err).Msgf("failed to get bootstrap peers from QBTC node, retrying... attempt %d/100", i+1)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(5 * time.Second):
				continue
			}
		}
		return bootstrapPeers, nil
	}
	return nil, fmt.Errorf("failed to get bootstrap peers from QBTC node after multiple attempts: %w", err)
}

// GetHost returns the p2p host
func (n *Network) GetHost() host.Host {
	return n.h
}

// Stop stops the p2p network
func (n *Network) Stop() error {
	if n.h == nil {
		return nil
	}
	if n.stopChan != nil {
		select {
		case <-n.stopChan:
		default:
			close(n.stopChan)
		}
	}
	n.wg.Wait()
	err := n.h.Close()
	n.h = nil
	if n.localDHT != nil {
		n.localDHT.Close()
		n.localDHT = nil
	}
	return err
}

// GetListenAddr returns the listen address
func (n *Network) GetListenAddr() maddr.Multiaddr {
	return n.listenAddr
}

// BootstrapInitialPeers connects to the given initial bootstrap peers
func (n *Network) BootstrapInitialPeers(initialPeers []peer.AddrInfo) error {
	bootstrapWg := sync.WaitGroup{}
	bootstrapWg.Add(len(initialPeers))
	for _, p := range initialPeers {
		peerInfo := p
		go func(p peer.AddrInfo) {
			defer bootstrapWg.Done()
			connectCtx, connectCancel := context.WithTimeout(context.Background(), bootstrapConnectTimeout)
			defer connectCancel()
			err := n.h.Connect(connectCtx, p)
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) || errors.Is(connectCtx.Err(), context.DeadlineExceeded) {
					n.logger.Warn().Err(err).Msgf("bootstrapper connect timed out: %s", p.String())
					return
				}
				n.logger.Err(err).Msgf("failed to connect to bootstrapper %s", p.String())
				return
			}
			n.h.ConnManager().TagPeer(p.ID, validatorTag, validatorTagValue)
			n.h.ConnManager().Protect(p.ID, validatorTag)
			n.logger.Info().Msgf("successfully connected to bootstrapper %s", p.String())
		}(peerInfo)
	}
	bootstrapWg.Wait()

	// Store initial validator peers
	n.validatorPeersMu.Lock()
	for _, p := range initialPeers {
		if p.ID == n.h.ID() {
			continue
		}
		n.validatorPeers[p.ID] = p
	}
	validatorCount := len(n.validatorPeers)
	n.validatorPeersMu.Unlock()
	if n.metrics != nil {
		n.metrics.SetGauge(metrics.MetricNameValidatorPeers, float64(validatorCount))
	}

	return nil
}

// ValidatorPeers returns the tracked validator peers (excluding self)
func (n *Network) ValidatorPeers() []peer.AddrInfo {
	n.validatorPeersMu.RLock()
	defer n.validatorPeersMu.RUnlock()
	peers := make([]peer.AddrInfo, 0, len(n.validatorPeers))
	for _, p := range n.validatorPeers {
		peers = append(peers, p)
	}
	return peers
}

// IsValidatorPeer returns true if the given peer ID is a known validator
func (n *Network) IsValidatorPeer(p peer.ID) bool {
	n.validatorPeersMu.RLock()
	_, ok := n.validatorPeers[p]
	n.validatorPeersMu.RUnlock()
	return ok
}

func (n *Network) startValidatorPeerRefresh(ctx context.Context) {
	defer n.wg.Done()
	ticker := time.NewTicker(validatorRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-n.stopChan:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.refreshValidatorPeers(ctx)
		}
	}
}

func (n *Network) refreshValidatorPeers(ctx context.Context) {
	refreshCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	newPeers, err := n.qBTCNode.GetBootstrapPeers(refreshCtx)
	if err != nil {
		n.logger.Error().Err(err).Msg("failed to refresh validator peers")
		return
	}
	if len(newPeers) == 0 {
		n.logger.Warn().Msg("validator peer refresh returned empty set; keeping existing peers")
		return
	}

	newSet := make(map[peer.ID]peer.AddrInfo, len(newPeers))
	for _, p := range newPeers {
		if p.ID == n.h.ID() {
			continue
		}
		newSet[p.ID] = p
	}

	n.validatorPeersMu.Lock()
	oldSet := n.validatorPeers
	n.validatorPeers = newSet
	n.validatorPeersMu.Unlock()

	// Tag new validators
	for id, p := range newSet {
		if _, existed := oldSet[id]; !existed {
			n.h.ConnManager().TagPeer(id, validatorTag, validatorTagValue)
			n.h.ConnManager().Protect(id, validatorTag)
			n.logger.Info().Str("peer", id.String()).Msg("tagged new validator peer")
			// Connect if not already connected
			if n.h.Network().Connectedness(id) != network.Connected {
				n.connectPeer(p)
			}
		}
	}

	// Untag removed validators
	for id := range oldSet {
		if _, exists := newSet[id]; !exists {
			n.h.ConnManager().UntagPeer(id, validatorTag)
			n.h.ConnManager().Unprotect(id, validatorTag)
			n.logger.Info().Str("peer", id.String()).Msg("untagged removed validator peer")
		}
	}

	if n.metrics != nil {
		n.metrics.SetGauge(metrics.MetricNameValidatorPeers, float64(len(newSet)))
	}
	n.logger.Info().Int("validator_peers", len(newSet)).Msg("refreshed validator peer set")
}

func (n *Network) connectValidatorPeer(p peer.AddrInfo) {
	n.wg.Add(1)
	go func(p peer.AddrInfo) {
		defer n.wg.Done()
		connectCtx, connectCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer connectCancel()
		if err := n.h.Connect(connectCtx, p); err != nil {
			n.logger.Warn().Err(err).Str("peer", p.ID.String()).Msg("failed to connect to new validator peer")
		}
	}(p)
}
