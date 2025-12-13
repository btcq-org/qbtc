package qclient

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/cosmos/cosmos-sdk/types/query"
	"github.com/libp2p/go-libp2p/core/peer"
	maddr "github.com/multiformats/go-multiaddr"
)

func (c *Client) GetLatestBtcBlockHeight(ctx context.Context) (uint64, error) {
	resp, err := c.qClient.LastProcessedBlock(ctx, &types.QueryLastProcessedBlockRequest{})
	if err != nil {
		return 0, err
	}
	return resp.Height, nil
}
func (c *Client) GetBootstrapPeers(ctx context.Context) ([]peer.AddrInfo, error) {
	resp, err := c.qClient.AllNodePeerAddresses(ctx, &types.QueryAllNodePeerAddressesRequest{
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
			c.logger.Warn().Msgf("invalid peer address format: %s", nodePeer.PeerAddress)
			continue
		}

		peerIDStr := parts[0]
		hostPort := parts[1]

		// Parse peer ID
		peerID, err := peer.Decode(peerIDStr)
		if err != nil {
			c.logger.Warn().Msgf("failed to decode peer ID: %s, err: %v", peerIDStr, err)
			continue
		}

		// Parse host:port
		host, port, err := net.SplitHostPort(hostPort)
		if err != nil {
			c.logger.Warn().Msgf("failed to parse host:port: %s, err: %v", hostPort, err)
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
