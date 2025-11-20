package p2p

import (
	"fmt"

	"github.com/btcq-org/qbtc/bifrost/keystore"
	config "github.com/btcq-org/qbtc/bifrost/types"

	qtypes "github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	quic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	maddr "github.com/multiformats/go-multiaddr"
)

// Network is the p2p network
type Network struct {
	config *config.P2PConfig

	listenAddr   maddr.Multiaddr
	externalAddr maddr.Multiaddr
	// p2p host
	h host.Host

	qClient *qtypes.QueryClient
}

// NewNetwork creates a new p2p network
func NewNetwork(config *config.P2PConfig, qClient *qtypes.QueryClient) *Network {
	return &Network{
		config:       config,
		listenAddr:   maddr.StringCast(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", config.Port)),
		externalAddr: maddr.StringCast(fmt.Sprintf("/ip4/%s/tcp/%d", config.ExternalIP, config.Port)),
		qClient:      qClient,
	}
}

// addressFactory is a function that returns the external address if it is set, otherwise returns the input addresses
func (n *Network) addressFactory(addrs []maddr.Multiaddr) []maddr.Multiaddr {
	if n.externalAddr != nil {
		return []maddr.Multiaddr{n.externalAddr}
	}
	return addrs
}

// Start starts the p2p network
func (n *Network) Start(key *keystore.PrivKey) error {
	privKey, err := crypto.UnmarshalPrivateKey(key.Body)
	if err != nil {
		return err
	}
	opts := []libp2p.Option{
		libp2p.ListenAddrs(n.listenAddr),
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

	return nil
}

// GetHost returns the p2p host
func (n *Network) GetHost() host.Host {
	return n.h
}

// Stop stops the p2p network
func (n *Network) Stop() error {
	return n.h.Close()
}

// GetListenAddr returns the listen address
func (n *Network) GetListenAddr() maddr.Multiaddr {
	return n.listenAddr
}
