package apptesting

import (
	"testing"
	"time"

	abci "github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/suite"

	sdkmath "cosmossdk.io/math"

	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"

	"github.com/btcq-org/qbtc/app"
	qbtctypes "github.com/btcq-org/qbtc/x/qbtc/types"
)

// IntegrationTestSuite is the base test suite for integration tests.
// It provides common setup and helper methods for testing the full app.
type IntegrationTestSuite struct {
	suite.Suite

	app       *app.App
	ctx       sdk.Context
	valSet    *cmttypes.ValidatorSet
	valKeys   []app.ValidatorKeyPair
	chainID   string
	govAddr   sdk.AccAddress
	bondDenom string

	// Test accounts
	testAccounts []sdk.AccAddress
	testPrivKeys []cryptotypes.PrivKey
}

// SetupTest initializes the app with validators before each test.
func (s *IntegrationTestSuite) SetupTest() {
	s.chainID = app.TestChainID

	// Create app with 3 validators
	s.app, s.valSet, s.valKeys = app.SetupWithValidators(s.T(), 3)

	// Get the context
	s.ctx = app.GetTestContext(s.app)

	// Get governance module address
	s.govAddr = authtypes.NewModuleAddress(govtypes.ModuleName)

	// Get bond denom
	s.bondDenom = app.DefaultTestDenom

	// Create test accounts with funds
	s.createTestAccounts(5)
}

// createTestAccounts creates test accounts with initial balances.
func (s *IntegrationTestSuite) createTestAccounts(num int) {
	s.testAccounts = make([]sdk.AccAddress, num)
	s.testPrivKeys = make([]cryptotypes.PrivKey, num)

	for i := 0; i < num; i++ {
		privKey := secp256k1.GenPrivKey()
		pubKey := privKey.PubKey()
		addr := sdk.AccAddress(pubKey.Address())

		s.testAccounts[i] = addr
		s.testPrivKeys[i] = privKey

		// Fund the account
		s.fundAccount(addr, sdk.NewCoins(sdk.NewCoin(s.bondDenom, sdkmath.NewInt(10_000_000_000))))
	}
}

// fundAccount mints coins and sends them to the specified address.
func (s *IntegrationTestSuite) fundAccount(addr sdk.AccAddress, coins sdk.Coins) {
	err := s.app.BankKeeper.MintCoins(s.ctx, qbtctypes.ReserveModuleName, coins)
	s.Require().NoError(err)

	err = s.app.BankKeeper.SendCoinsFromModuleToAccount(s.ctx, qbtctypes.ReserveModuleName, addr, coins)
	s.Require().NoError(err)
}

// advanceBlock advances the chain by one block.
func (s *IntegrationTestSuite) advanceBlock() {
	header := cmtproto.Header{
		Height:  s.app.LastBlockHeight() + 1,
		ChainID: s.chainID,
		Time:    time.Now().UTC(),
	}

	_, err := s.app.FinalizeBlock(&abci.RequestFinalizeBlock{
		Height:             header.Height,
		Time:               header.Time,
		NextValidatorsHash: s.valSet.Hash(),
	})
	s.Require().NoError(err)

	_, err = s.app.Commit()
	s.Require().NoError(err)

	s.ctx = s.app.BaseApp.NewUncachedContext(false, header)
}

// getBalance returns the balance of the given address.
func (s *IntegrationTestSuite) getBalance(addr sdk.AccAddress, denom string) sdk.Coin {
	return s.app.BankKeeper.GetBalance(s.ctx, addr, denom)
}

// TestIntegrationTestSuite runs the integration test suite.
func TestIntegrationTestSuite(t *testing.T) {
	suite.Run(t, new(IntegrationTestSuite))
}

// TestSetup verifies that the test suite setup works correctly.
func (s *IntegrationTestSuite) TestSetup() {
	// Verify app is initialized
	s.Require().NotNil(s.app)

	// Verify validators are set up
	s.Require().Equal(3, len(s.valKeys))

	// Verify test accounts are created
	s.Require().Equal(5, len(s.testAccounts))

	// Verify test accounts have balances
	for _, addr := range s.testAccounts {
		balance := s.getBalance(addr, s.bondDenom)
		s.Require().False(balance.IsZero(), "test account should have balance")
	}

	// Verify governance address
	s.Require().NotNil(s.govAddr)

	// Verify we can advance blocks
	initialHeight := s.app.LastBlockHeight()
	s.advanceBlock()
	s.Require().Equal(initialHeight+1, s.app.LastBlockHeight())
}
