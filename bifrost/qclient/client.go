package qclient

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/btcq-org/qbtc/common"
	ebifrost "github.com/btcq-org/qbtc/x/qbtc/ebifrost"
	qtypes "github.com/btcq-org/qbtc/x/qbtc/types"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
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
	ebifrost      ebifrost.LocalhostBifrostClient
	logger        zerolog.Logger

	// cached validators
	validatorsMu     sync.RWMutex
	activeValidators []stakingtypes.Validator
	lastUpdateTime   time.Time
	registry         codectypes.InterfaceRegistry
}

type QBTCNode interface {
	GetBootstrapPeers(ctx context.Context) ([]peer.AddrInfo, error)
	VerifyAttestation(ctx context.Context, block qtypes.BlockGossip) error
	CheckAttestationsSuperMajority(ctx context.Context, msg *qtypes.MsgBtcBlock) error
}

var _ QBTCNode = &Client{}

func NewGRPCConnection(target string, insecure bool) (*grpc.ClientConn, error) {
	if insecure {
		conn, err := grpc.NewClient(target,
			grpc.WithTransportCredentials(insecurecreds.NewCredentials()),
			grpc.WithContextDialer(dialerFunc))
		if err != nil {
			return nil, err
		}
		return conn, nil
	}

	conn, err := grpc.NewClient(
		target,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS13,
		})),
	)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// New creates a new query client for QBTC blockchain node at the given target address.
func New(target string, insecure bool) (*Client, error) {
	conn, err := NewGRPCConnection(target, insecure)
	if err != nil {
		return nil, err
	}

	return clientWithConn(conn), nil
}

func clientWithConn(conn *grpc.ClientConn) *Client {
	registry := codectypes.NewInterfaceRegistry()
	cryptocodec.RegisterInterfaces(registry)
	return &Client{
		conn:             conn,
		qClient:          qtypes.NewQueryClient(conn),
		stakingClient:    stakingtypes.NewQueryClient(conn),
		logger:           log.With().Str("module", "qclient").Logger(),
		activeValidators: make([]stakingtypes.Validator, 0),
		lastUpdateTime:   time.Now().Add(-time.Minute),
		registry:         registry,
	}
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

func init() {
	accountPubKeyPrefix := common.AccountAddressPrefix + "pub"
	validatorAddressPrefix := common.AccountAddressPrefix + "valoper"
	validatorPubKeyPrefix := common.AccountAddressPrefix + "valoperpub"
	consNodeAddressPrefix := common.AccountAddressPrefix + "valcons"
	consNodePubKeyPrefix := common.AccountAddressPrefix + "valconspub"

	config := sdk.GetConfig()
	config.SetBech32PrefixForAccount(common.AccountAddressPrefix, accountPubKeyPrefix)
	config.SetBech32PrefixForValidator(validatorAddressPrefix, validatorPubKeyPrefix)
	config.SetBech32PrefixForConsensusNode(consNodeAddressPrefix, consNodePubKeyPrefix)
	config.Seal()
}
