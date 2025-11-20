package p2p

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/btcq-org/qbtc/bifrost/keystore"
	config "github.com/btcq-org/qbtc/bifrost/types"

	qclient "github.com/btcq-org/qbtc/bifrost/qclient"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	quic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	maddr "github.com/multiformats/go-multiaddr"
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
}

// NewNetwork creates a new p2p network
func NewNetwork(config *config.P2PConfig, qBTCNode qclient.QBTCNode) *Network {
	n := &Network{
		config:         config,
		listenAddr:     maddr.StringCast(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", config.Port)),
		listenAddrQUIC: maddr.StringCast(fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic", config.Port)),
		qBTCNode:       qBTCNode,
	}

	if config.ExternalIP != "" {
		n.externalAddr = maddr.StringCast(fmt.Sprintf("/ip4/%s/tcp/%d", config.ExternalIP, config.Port))
		n.externalAddrQUIC = maddr.StringCast(fmt.Sprintf("/ip4/%s/udp/%d/quic", config.ExternalIP, config.Port))
	}
	return n
}

// addressFactory is a function that returns the external address if it is set, otherwise returns the input addresses
func (n *Network) addressFactory(addrs []maddr.Multiaddr) []maddr.Multiaddr {
	if n.externalAddr != nil {
		// Return both TCP and QUIC external addresses
		return []maddr.Multiaddr{n.externalAddr, n.externalAddrQUIC}
	}
	return addrs
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
	return n.h.Close()
}

// GetListenAddr returns the listen address
func (n *Network) GetListenAddr() maddr.Multiaddr {
	return n.listenAddr
}

func setupDHT(ctx context.Context, host host.Host, initialPeers []peer.AddrInfo) (*dht.IpfsDHT, error) {
	dht, err := dht.New(ctx, host)
	if err != nil {
		return nil, err
	}
	err = dht.Bootstrap(ctx)
	if err != nil {
		return nil, err
	}
	wg := sync.WaitGroup{}
	wg.Add(len(initialPeers))
	for _, p := range initialPeers {
		go func() {
			defer wg.Done()

			err := host.Connect(ctx, p)
			if err != nil {
				slog.Error("failed to connect to bootstrapper", "peer", p, "err", err)
				return
			}
			slog.Info("successfully connected to bootstrapper", "peer", p.String())
		}()
	}
	wg.Wait()
	if err != nil {
		return nil, err
	}

	return dht, nil
}
