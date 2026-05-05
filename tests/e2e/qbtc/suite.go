package qbtc

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/cosmos/cosmos-sdk/testutil/network"
	"github.com/stretchr/testify/suite"

	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/btcq-org/qbtc/x/qbtc/zk"
)

// e2eChainID is fixed so the ZK proof can be bound to the same chain ID the
// test network runs with. cosmos-sdk's DefaultConfig otherwise picks a random
// one and the proof would fail verification.
const e2eChainID = "qbtc-e2e-1"

// E2ETestSuite drives the qbtc module's tx and query flows against an
// in-process qbtc network. Follows the cosmos-sdk per-module e2e template:
// suite struct + constructor + SetupSuite/TearDownSuite, with tx test methods
// kept in tx.go and (future) query tests in grpc.go.
type E2ETestSuite struct {
	suite.Suite

	cfg     network.Config
	network *network.Network

	// ZK + BTC state shared between SetupSuite (genesis seeding) and the
	// tx test methods (proof generation).
	setup       *zk.SetupResult
	btcPrivKey  *btcec.PrivateKey
	addressHash [20]byte
	btcAddress  string
	seedUTXOs   []*types.UTXO
}

// NewE2ETestSuite matches the SDK convention: the entrypoint hands us a fully
// initialized network.Config (including the custom fixture), and the suite
// takes it from there.
func NewE2ETestSuite(cfg network.Config) *E2ETestSuite {
	return &E2ETestSuite{cfg: cfg}
}

func (s *E2ETestSuite) SetupSuite() {
	s.T().Log("setting up qbtc e2e test suite")

	// 1. Trusted setup (test SRS — NOT for production use).
	setup, err := zk.SetupWithOptions(zk.TestSetupOptions())
	s.Require().NoError(err)
	s.setup = setup

	vkBytes, err := zk.SerializeVerifyingKey(setup.VerifyingKey)
	s.Require().NoError(err)

	// 2. Test BTC keypair that "owns" the seeded UTXOs.
	priv, err := btcec.NewPrivateKey()
	s.Require().NoError(err)
	s.btcPrivKey = priv

	addrHash, err := zk.PrivateKeyToAddressHash(priv)
	s.Require().NoError(err)
	s.addressHash = addrHash

	btcAddr, err := zk.Hash160ToP2PKHAddress(addrHash)
	s.Require().NoError(err)
	s.btcAddress = btcAddr

	s.seedUTXOs = []*types.UTXO{
		{
			Txid:           "aaaa000000000000000000000000000000000000000000000000000000000001",
			Vout:           0,
			Amount:         100_000_000,
			EntitledAmount: 50_000_000,
			ScriptPubKey:   &types.ScriptPubKeyResult{Address: btcAddr},
		},
		{
			Txid:           "aaaa000000000000000000000000000000000000000000000000000000000002",
			Vout:           1,
			Amount:         200_000_000,
			EntitledAmount: 150_000_000,
			ScriptPubKey:   &types.ScriptPubKeyResult{Address: btcAddr},
		},
	}

	// 3. Mutate the qbtc module genesis in place — the SDK pattern for
	// seeding module-specific state before the network starts.
	qbtcGen := &types.GenesisState{
		ZkVerifyingKey: vkBytes,
		Utxos:          s.seedUTXOs,
	}
	s.cfg.GenesisState[types.ModuleName] = s.cfg.Codec.MustMarshalJSON(qbtcGen)

	s.network, err = network.New(s.T(), s.T().TempDir(), s.cfg)
	s.Require().NoError(err)
	s.Require().NoError(s.network.WaitForNextBlock())
}

func (s *E2ETestSuite) TearDownSuite() {
	s.T().Log("tearing down qbtc e2e test suite")
	s.network.Cleanup()
}
