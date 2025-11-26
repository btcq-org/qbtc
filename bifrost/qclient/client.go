package qclient

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"sync"
	"time"

	qtypes "github.com/btcq-org/qbtc/x/qbtc/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	insecurecreds "google.golang.org/grpc/credentials/insecure"
)

type Client struct {
	conn          *grpc.ClientConn
	qClient       qtypes.QueryClient
	stakingClient stakingtypes.QueryClient
	logger        zerolog.Logger

	// cached validators
	validatorsMu     sync.RWMutex
	activeValidators []stakingtypes.Validator
	lastUpdateTime   time.Time
}

type QBTCNode interface {
	GetBootstrapPeers(ctx context.Context) ([]peer.AddrInfo, error)
	VerifyAttestation(ctx context.Context, block qtypes.BlockGossip) error
	CheckAttestationsSuperMajority(ctx context.Context, msg *qtypes.MsgBtcBlock) error
}

var _ QBTCNode = &Client{}

// New creates a new query client for QBTC blockchain node at the given target address.
func New(target string, insecure bool) (*Client, error) {
	var conn *grpc.ClientConn
	var err error
	if insecure {
		conn, err = grpc.NewClient(target,
			grpc.WithTransportCredentials(insecurecreds.NewCredentials()),
			grpc.WithContextDialer(dialerFunc))
		if err != nil {
			return nil, err
		}

		return &Client{
			conn:             conn,
			qClient:          qtypes.NewQueryClient(conn),
			stakingClient:    stakingtypes.NewQueryClient(conn),
			logger:           log.With().Str("module", "qclient").Logger(),
			activeValidators: make([]stakingtypes.Validator, 0),
			lastUpdateTime:   time.Now().Add(-time.Minute),
		}, nil
	}

	conn, err = grpc.NewClient(
		target,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS13,
		})),
	)
	if err != nil {
		return nil, err
	}
	return &Client{
		conn:          conn,
		qClient:       qtypes.NewQueryClient(conn),
		stakingClient: stakingtypes.NewQueryClient(conn),
		logger:        log.With().Str("module", "qclient").Logger(),
	}, nil
}

func (c *Client) WithStakingClient(stakingClient stakingtypes.QueryClient) *Client {
	c.stakingClient = stakingClient
	return c
}

func dialerFunc(_ context.Context, addr string) (net.Conn, error) {
	return connect(addr)
}

func connect(protoAddr string) (net.Conn, error) {
	proto, address := protocolAndAddress(protoAddr)
	conn, err := net.Dial(proto, address)
	return conn, err
}

func protocolAndAddress(listenAddr string) (string, string) {
	protocol, address := "tcp", listenAddr

	parts := strings.SplitN(address, "://", 2)
	if len(parts) == 2 {
		protocol, address = parts[0], parts[1]
	}

	return protocol, address
}

func (c *Client) Close() error {
	return c.conn.Close()
}
