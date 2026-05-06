package qbtc

import (
	"testing"

	"github.com/cosmos/cosmos-sdk/testutil/network"
	"github.com/stretchr/testify/suite"

	apptestutil "github.com/btcq-org/qbtc/app/testutil"
)

// TestE2ETestSuite wires cosmos-sdk's testutil/network harness to our
// suite. Matches the shape of the SDK's per-module e2e entrypoints
// (e.g. tests/e2e/bank/cli_test.go).
func TestE2ETestSuite(t *testing.T) {
	cfg := network.DefaultConfig(apptestutil.NewTestNetworkFixture)
	cfg.NumValidators = 1
	// Pin the chain ID so proofs minted inside the suite can bind to a
	// known chain. DefaultConfig otherwise picks a random one.
	cfg.ChainID = e2eChainID

	suite.Run(t, NewE2ETestSuite(cfg))
}
