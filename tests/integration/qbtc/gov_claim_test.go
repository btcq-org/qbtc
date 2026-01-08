package qbtc_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	sdkmath "cosmossdk.io/math"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"
	govv1 "github.com/cosmos/cosmos-sdk/x/gov/types/v1"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	qbtctypes "github.com/btcq-org/qbtc/x/qbtc/types"
)

// GovClaimTestSuite tests MsgGovClaimUTXO message handling.
type GovClaimTestSuite struct {
	IntegrationTestSuite
	msgServer qbtctypes.MsgServer
}

func TestGovClaimTestSuite(t *testing.T) {
	suite.Run(t, new(GovClaimTestSuite))
}

func (s *GovClaimTestSuite) SetupTest() {
	s.IntegrationTestSuite.SetupTest()
	s.msgServer = keeper.NewMsgServerImpl(s.app.QbtcKeeper)
}

// getUTXOKey returns the UTXO key in the format used by the keeper (txid-vout).
func getUTXOKey(txid string, vout uint32) string {
	return fmt.Sprintf("%s-%d", txid, vout)
}

// setupTestUTXO creates a test UTXO in the keeper state.
func (s *GovClaimTestSuite) setupTestUTXO(txid string, vout uint32, amount, entitledAmount uint64) {
	utxo := qbtctypes.UTXO{
		Txid:           txid,
		Vout:           vout,
		Amount:         amount,
		EntitledAmount: entitledAmount,
		ScriptPubKey: &qbtctypes.ScriptPubKeyResult{
			Hex:     "76a91488ac",
			Type:    "pubkeyhash",
			Address: "1J6QsrCXRTZusGEeyg44BcoqgM4SZXTXhC",
		},
	}
	key := getUTXOKey(txid, vout)
	err := s.app.QbtcKeeper.Utxoes.Set(s.ctx, key, utxo)
	s.Require().NoError(err)
}

func (s *GovClaimTestSuite) TestGovClaimUTXO_WithGovernanceAuthority() {
	// Set up a test UTXO
	txid := "0000000000000000000000000000000000000000000000000000000000000001"
	s.setupTestUTXO(txid, 0, 100000000, 50000000)

	govAddr := authtypes.NewModuleAddress(govtypes.ModuleName)

	msg := &qbtctypes.MsgGovClaimUTXO{
		Authority: govAddr.String(),
		Utxos: []*qbtctypes.ClaimUTXO{
			{Txid: txid, Vout: 0},
		},
	}

	ctx := s.ctx
	_, err := s.msgServer.GovClaimUTXO(ctx, msg)
	s.Require().NoError(err, "governance should be able to claim UTXO")

	// Verify the UTXO entitled amount was set to 0
	utxo, err := s.app.QbtcKeeper.Utxoes.Get(ctx, getUTXOKey(txid, 0))
	s.Require().NoError(err)
	s.Require().Equal(uint64(0), utxo.EntitledAmount, "entitled amount should be set to 0 after claim")
	s.Require().Equal(uint64(100000000), utxo.Amount, "original amount should remain unchanged")
}

func (s *GovClaimTestSuite) TestGovClaimUTXO_WithWrongAuthority() {
	// Set up a test UTXO
	txid := "0000000000000000000000000000000000000000000000000000000000000002"
	s.setupTestUTXO(txid, 0, 100000000, 50000000)

	// Use a non-governance address
	wrongAuthority := s.testAccounts[0]

	msg := &qbtctypes.MsgGovClaimUTXO{
		Authority: wrongAuthority.String(),
		Utxos: []*qbtctypes.ClaimUTXO{
			{Txid: txid, Vout: 0},
		},
	}

	ctx := s.ctx
	_, err := s.msgServer.GovClaimUTXO(ctx, msg)
	s.Require().Error(err, "non-governance address should not be able to claim UTXO")
}

func (s *GovClaimTestSuite) TestGovClaimUTXO_WithEmptyAuthority() {
	msg := &qbtctypes.MsgGovClaimUTXO{
		Authority: "",
		Utxos: []*qbtctypes.ClaimUTXO{
			{Txid: "sometxid", Vout: 0},
		},
	}

	ctx := s.ctx
	_, err := s.msgServer.GovClaimUTXO(ctx, msg)
	s.Require().Error(err, "empty authority should be rejected")
}

func (s *GovClaimTestSuite) TestGovClaimUTXO_WithNoUTXOs() {
	govAddr := authtypes.NewModuleAddress(govtypes.ModuleName)

	msg := &qbtctypes.MsgGovClaimUTXO{
		Authority: govAddr.String(),
		Utxos:     []*qbtctypes.ClaimUTXO{},
	}

	ctx := s.ctx
	_, err := s.msgServer.GovClaimUTXO(ctx, msg)
	s.Require().Error(err, "empty UTXOs list should be rejected")
}

func (s *GovClaimTestSuite) TestGovClaimUTXO_UTXONotFound() {
	govAddr := authtypes.NewModuleAddress(govtypes.ModuleName)

	// Try to claim a non-existent UTXO
	msg := &qbtctypes.MsgGovClaimUTXO{
		Authority: govAddr.String(),
		Utxos: []*qbtctypes.ClaimUTXO{
			{Txid: "nonexistent_txid_12345", Vout: 0},
		},
	}

	ctx := s.ctx
	_, err := s.msgServer.GovClaimUTXO(ctx, msg)
	s.Require().Error(err, "non-existent UTXO should cause an error")
}

func (s *GovClaimTestSuite) TestGovClaimUTXO_MultipleUTXOs() {
	// Set up multiple test UTXOs
	txid1 := "1111111111111111111111111111111111111111111111111111111111111111"
	txid2 := "2222222222222222222222222222222222222222222222222222222222222222"
	txid3 := "3333333333333333333333333333333333333333333333333333333333333333"

	s.setupTestUTXO(txid1, 0, 100000000, 50000000)
	s.setupTestUTXO(txid2, 1, 200000000, 150000000)
	s.setupTestUTXO(txid3, 2, 300000000, 250000000)

	govAddr := authtypes.NewModuleAddress(govtypes.ModuleName)

	msg := &qbtctypes.MsgGovClaimUTXO{
		Authority: govAddr.String(),
		Utxos: []*qbtctypes.ClaimUTXO{
			{Txid: txid1, Vout: 0},
			{Txid: txid2, Vout: 1},
			{Txid: txid3, Vout: 2},
		},
	}

	ctx := s.ctx
	_, err := s.msgServer.GovClaimUTXO(ctx, msg)
	s.Require().NoError(err, "governance should be able to claim multiple UTXOs")

	// Verify all UTXOs were claimed
	utxo1, err := s.app.QbtcKeeper.Utxoes.Get(ctx, getUTXOKey(txid1, 0))
	s.Require().NoError(err)
	s.Require().Equal(uint64(0), utxo1.EntitledAmount)

	utxo2, err := s.app.QbtcKeeper.Utxoes.Get(ctx, getUTXOKey(txid2, 1))
	s.Require().NoError(err)
	s.Require().Equal(uint64(0), utxo2.EntitledAmount)

	utxo3, err := s.app.QbtcKeeper.Utxoes.Get(ctx, getUTXOKey(txid3, 2))
	s.Require().NoError(err)
	s.Require().Equal(uint64(0), utxo3.EntitledAmount)
}

func (s *GovClaimTestSuite) TestGovClaimUTXO_AlreadyClaimed() {
	// Set up a UTXO with zero entitled amount (already claimed)
	txid := "4444444444444444444444444444444444444444444444444444444444444444"
	s.setupTestUTXO(txid, 0, 100000000, 0) // EntitledAmount = 0

	govAddr := authtypes.NewModuleAddress(govtypes.ModuleName)

	msg := &qbtctypes.MsgGovClaimUTXO{
		Authority: govAddr.String(),
		Utxos: []*qbtctypes.ClaimUTXO{
			{Txid: txid, Vout: 0},
		},
	}

	ctx := s.ctx
	// This should succeed but not mint any coins (since entitled amount is 0)
	_, err := s.msgServer.GovClaimUTXO(ctx, msg)
	s.Require().NoError(err, "claiming already-claimed UTXO should not error")

	// Verify UTXO still has zero entitled amount
	utxo, err := s.app.QbtcKeeper.Utxoes.Get(ctx, getUTXOKey(txid, 0))
	s.Require().NoError(err)
	s.Require().Equal(uint64(0), utxo.EntitledAmount)
}

func (s *GovClaimTestSuite) TestGovClaimUTXO_InvalidTxid() {
	govAddr := authtypes.NewModuleAddress(govtypes.ModuleName)

	msg := &qbtctypes.MsgGovClaimUTXO{
		Authority: govAddr.String(),
		Utxos: []*qbtctypes.ClaimUTXO{
			{Txid: "", Vout: 0}, // Empty txid
		},
	}

	ctx := s.ctx
	_, err := s.msgServer.GovClaimUTXO(ctx, msg)
	s.Require().Error(err, "empty txid should be rejected")
}

// TestGovClaimUTXO_FullGovernanceProposalFlow tests the complete governance proposal flow:
// 1. Submit a proposal to claim UTXO
// 2. Vote on the proposal
// 3. Advance time to pass voting period
// 4. Execute endblocker to process the proposal
// 5. Verify the proposal passed and UTXO was claimed
func (s *GovClaimTestSuite) TestGovClaimUTXO_FullGovernanceProposalFlow() {
	ctx := s.ctx

	// Set up a test UTXO
	txid := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	s.setupTestUTXO(txid, 0, 100000000, 50000000)

	// Verify initial state
	utxoBefore, err := s.app.QbtcKeeper.Utxoes.Get(ctx, getUTXOKey(txid, 0))
	s.Require().NoError(err)
	s.Require().Equal(uint64(50000000), utxoBefore.EntitledAmount, "initial entitled amount should be 50000000")

	// Get the first validator address for delegation
	valAddr := sdk.ValAddress(s.valKeys[0].Address)
	validator, err := s.app.StakingKeeper.Validator(ctx, valAddr)
	s.Require().NoError(err)
	s.Require().NotNil(validator)

	// Delegate tokens from test accounts to validators to get voting power
	// We need enough voting power to meet quorum and threshold
	delegationAmount := sdkmath.NewInt(1_000_000_000)
	fundAmount := sdkmath.NewInt(2_000_000_000)
	for i := 0; i < len(s.testAccounts) && i < 3; i++ {
		// Fund delegator with bond-denom tokens for staking and deposit
		fundCoins := sdk.NewCoins(sdk.NewCoin(sdk.DefaultBondDenom, fundAmount))
		err := s.app.BankKeeper.MintCoins(ctx, qbtctypes.ReserveModuleName, fundCoins)
		s.Require().NoError(err)
		err = s.app.BankKeeper.SendCoinsFromModuleToAccount(ctx, qbtctypes.ReserveModuleName, s.testAccounts[i], fundCoins)
		s.Require().NoError(err)

		delMsg := &stakingtypes.MsgDelegate{
			DelegatorAddress: s.testAccounts[i].String(),
			ValidatorAddress: validator.GetOperator(),
			Amount:           sdk.NewCoin(sdk.DefaultBondDenom, delegationAmount),
		}
		result := s.submitTxExpectSuccess(delMsg, s.testAccounts[i], s.testPrivKeys[i])
		s.Require().True(result.IsOK(), "delegation should succeed")
	}

	// Advance a block to ensure delegation is processed
	s.advanceBlock()

	// Create the proposal message
	govAddr := authtypes.NewModuleAddress(govtypes.ModuleName)
	claimMsg := &qbtctypes.MsgGovClaimUTXO{
		Authority: govAddr.String(),
		Utxos: []*qbtctypes.ClaimUTXO{
			{Txid: txid, Vout: 0},
		},
	}

	// Pack the message into Any
	claimMsgAny, err := codectypes.NewAnyWithValue(claimMsg)
	s.Require().NoError(err)

	// Minimum deposit for the proposal (use a fixed, reasonable value with correct bond denom)
	minDeposit := sdk.NewCoins(sdk.NewCoin(sdk.DefaultBondDenom, sdkmath.NewInt(100_000_000)))

	// Submit the proposal
	proposer := s.testAccounts[0]
	submitMsg := &govv1.MsgSubmitProposal{
		Messages:       []*codectypes.Any{claimMsgAny},
		InitialDeposit: minDeposit,
		Proposer:       proposer.String(),
		Metadata:       "Test proposal to claim UTXO",
		Title:          "Claim UTXO via Governance",
		Summary:        "This proposal claims a test UTXO",
	}

	result := s.submitTxExpectSuccess(submitMsg, proposer, s.testPrivKeys[0])
	s.Require().True(result.IsOK(), "proposal submission should succeed")

	// Extract proposal ID from events
	var proposalID uint64
	for _, event := range result.Events {
		if event.Type == "submit_proposal" {
			for _, attr := range event.Attributes {
				if string(attr.Key) == "proposal_id" {
					// Parse proposal ID
					_, err := fmt.Sscanf(string(attr.Value), "%d", &proposalID)
					s.Require().NoError(err)
					break
				}
			}
		}
	}
	s.Require().NotZero(proposalID, "proposal ID should be extracted from events")

	// Vote on the proposal with Yes votes from multiple accounts
	// We need enough votes to meet quorum and threshold
	for i := 0; i < len(s.testAccounts) && i < 3; i++ {
		voteMsg := &govv1.MsgVote{
			ProposalId: proposalID,
			Voter:      s.testAccounts[i].String(),
			Option:     govv1.OptionYes,
		}
		result := s.submitTxExpectSuccess(voteMsg, s.testAccounts[i], s.testPrivKeys[i])
		s.Require().True(result.IsOK(), "vote should succeed")
	}

	// Advance a block to process votes
	s.advanceBlock()

	// Advance time to pass the voting period (use a fixed voting period)
	votingPeriod := 24 * time.Hour
	// Advance time by voting period + 1 hour to ensure it passes
	// This will trigger EndBlocker which should process the proposal
	s.advanceBlockWithTime(votingPeriod + time.Hour)

	// Verify the UTXO was claimed (entitled amount should be 0)
	utxoAfter, err := s.app.QbtcKeeper.Utxoes.Get(s.ctx, getUTXOKey(txid, 0))
	s.Require().NoError(err)
	s.Require().Equal(uint64(0), utxoAfter.EntitledAmount, "entitled amount should be 0 after governance claim")
	s.Require().Equal(uint64(100000000), utxoAfter.Amount, "original amount should remain unchanged")
}
