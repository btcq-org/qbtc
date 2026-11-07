package qbtc

import (
	"testing"

	cmtmldsa65 "github.com/cometbft/cometbft/crypto/mldsa65"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
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
	// The chain accepts ML-DSA-65 keys only, for validators and accounts alike:
	// pub_key_types in genesis, the validators' consensus keys, and the keyring
	// the suite signs with.
	cfg.ValidatorConsensusKeyType = cmtmldsa65.KeyType
	cfg.SigningAlgo = string(hd.MlDsa65Type)
	cfg.KeyringOptions = []keyring.Option{func(o *keyring.Options) {
		o.SupportedAlgos = keyring.SigningAlgoList{hd.MlDsa65}
		o.SupportedAlgosLedger = nil
	}}

	suite.Run(t, NewE2ETestSuite(cfg))
}
