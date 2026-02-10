package tokenfactory

import (
	"testing"

	"github.com/cosmos/cosmos-sdk/testutil/network"
	"github.com/stretchr/testify/suite"
)

// TokenFactoryIntegrationSuite runs end-to-end tests against a real
// in-process test network with the full qbtc app (IBC, WASM, tokenfactory).
type TokenFactoryIntegrationSuite struct {
	suite.Suite

	cfg     network.Config
	network *network.Network
}

func (s *TokenFactoryIntegrationSuite) SetupSuite() {
	s.T().Log("setting up token factory e2e integration test suite")

	cfg := network.DefaultConfig(func() network.TestFixture {
		return NewTestNetworkFixture(s.T().TempDir())
	})
	cfg.NumValidators = 1

	var err error
	s.cfg = cfg
	s.network, err = network.New(s.T(), s.T().TempDir(), cfg)
	s.Require().NoError(err)

	// Wait for the first block so we can broadcast transactions.
	s.Require().NoError(s.network.WaitForNextBlock())
}

func (s *TokenFactoryIntegrationSuite) TearDownSuite() {
	s.T().Log("tearing down token factory e2e integration test suite")
	s.network.Cleanup()
}

func TestTokenFactoryIntegration(t *testing.T) {
	suite.Run(t, new(TokenFactoryIntegrationSuite))
}
