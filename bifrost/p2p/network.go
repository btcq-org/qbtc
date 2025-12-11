package p2p

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/btcq-org/qbtc/bifrost/config"
	"github.com/btcq-org/qbtc/bifrost/keystore"
	"github.com/btcq-org/qbtc/bifrost/metrics"
	qclient "github.com/btcq-org/qbtc/bifrost/qclient"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	quic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	maddr "github.com/multiformats/go-multiaddr"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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
	}
	host, err := libp2p.New(opts...)
	if err != nil {
		return err
	}
	n.h = host
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

	bootstrapPeers, err := n.qBTCNode.GetBootstrapPeers(ctx)
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
	return nil
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
	err := n.h.Close()
	n.h = nil
	n.localDHT.Close()
	n.localDHT = nil
	return err
}

// GetListenAddr returns the listen address
func (n *Network) GetListenAddr() maddr.Multiaddr {
	return n.listenAddr
}

// BootstrapInitialPeers connects to the given initial bootstrap peers
func (n *Network) BootstrapInitialPeers(initialPeers []peer.AddrInfo) error {
	wg := sync.WaitGroup{}
	wg.Add(len(initialPeers))
	for _, p := range initialPeers {
		go func() {
			defer wg.Done()
			err := n.h.Connect(context.Background(), p)
			if err != nil {
				n.logger.Err(err).Msgf("failed to connect to bootstrapper %s", p.String())
				return
			}
			n.logger.Info().Msgf("successfully connected to bootstrapper %s", p.String())
		}()
	}
	wg.Wait()
	return nil
}
