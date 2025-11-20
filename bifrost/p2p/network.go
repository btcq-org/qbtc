package p2p

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/btcq-org/qbtc/bifrost/keystore"
	config "github.com/btcq-org/qbtc/bifrost/types"
	"github.com/cosmos/cosmos-sdk/types/query"

	"github.com/btcq-org/qbtc/x/qbtc/types"
	qtypes "github.com/btcq-org/qbtc/x/qbtc/types"
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

	qClient qtypes.QueryClient
}

// NewNetwork creates a new p2p network
func NewNetwork(config *config.P2PConfig, qClient qtypes.QueryClient) *Network {
	n := &Network{
		config:         config,
		listenAddr:     maddr.StringCast(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", config.Port)),
		listenAddrQUIC: maddr.StringCast(fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic", config.Port)),
		qClient:        qClient,
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

func getBootstrapPeers(ctx context.Context, qClient qtypes.QueryClient) ([]peer.AddrInfo, error) {
	resp, err := qClient.AllNodePeerAddresses(ctx, &types.QueryAllNodePeerAddressesRequest{
		Pagination: &query.PageRequest{
			Limit: 100,
		},
	})
	if err != nil {
		return nil, err
	}

	var addrInfos []peer.AddrInfo
	for _, nodePeer := range resp.NodePeerAddresses {
		// Parse peer address in format: <peerID>@<host>:<port>
		parts := strings.Split(nodePeer.PeerAddress, "@")
		if len(parts) != 2 {
			slog.Warn("invalid peer address format", "address", nodePeer.PeerAddress)
			continue
		}

		peerIDStr := parts[0]
		hostPort := parts[1]

		// Parse peer ID
		peerID, err := peer.Decode(peerIDStr)
		if err != nil {
			slog.Warn("failed to decode peer ID", "peerID", peerIDStr, "err", err)
			continue
		}

		// Parse host:port
		host, port, err := net.SplitHostPort(hostPort)
		if err != nil {
			slog.Warn("failed to parse host:port", "hostPort", hostPort, "err", err)
			continue
		}

		// Create multiaddr from host and port
		// Try to determine if it's IPv4 or IPv6
		// Create both TCP and QUIC addresses
		var addrs []maddr.Multiaddr
		if ip := net.ParseIP(host); ip != nil {
			if ip.To4() != nil {
				// IPv4 - create both TCP and QUIC addresses
				addrs = []maddr.Multiaddr{
					maddr.StringCast(fmt.Sprintf("/ip4/%s/tcp/%s", host, port)),
					maddr.StringCast(fmt.Sprintf("/ip4/%s/udp/%s/quic", host, port)),
				}
			} else {
				// IPv6 - create both TCP and QUIC addresses
				addrs = []maddr.Multiaddr{
					maddr.StringCast(fmt.Sprintf("/ip6/%s/tcp/%s", host, port)),
					maddr.StringCast(fmt.Sprintf("/ip6/%s/udp/%s/quic", host, port)),
				}
			}
		} else {
			// Domain name - create both TCP and QUIC addresses
			addrs = []maddr.Multiaddr{
				maddr.StringCast(fmt.Sprintf("/dns/%s/tcp/%s", host, port)),
				maddr.StringCast(fmt.Sprintf("/dns/%s/udp/%s/quic", host, port)),
			}
		}

		// Create AddrInfo with both TCP and QUIC addresses
		addrInfo := peer.AddrInfo{
			ID:    peerID,
			Addrs: addrs,
		}

		addrInfos = append(addrInfos, addrInfo)
	}

	return addrInfos, nil
}
