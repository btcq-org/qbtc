package qbtc

import (
	"context"
	"encoding/hex"
	"fmt"

	sdkmath "cosmossdk.io/math"

	"github.com/cosmos/cosmos-sdk/client/flags"
	clitestutil "github.com/cosmos/cosmos-sdk/testutil/cli"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"

	qbtcclitestutil "github.com/btcq-org/qbtc/x/qbtc/client/testutil"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/btcq-org/qbtc/x/qbtc/zk"
	"github.com/btcq-org/qbtc/x/qbtc/zk/zktest"
)

// TestClaimWithProofCmd drives the `tx qbtc claim-with-proof` command through
// the standard SDK CLI plumbing and asserts the DeliverTx result for each
// scenario. Table rows cover the happy path plus the replay-after-claim case;
// more scenarios (wrong claimer, partial match) can slot in without changing
// the shape.
func (s *E2ETestSuite) TestClaimWithProofCmd() {
	val := s.network.Validators[0]
	claimer := val.Address.String()

	// Pre-claim balance baseline. Captured once before the table runs so
	// each row can compute its own expected delta.
	preBal := s.queryBalance(claimer, s.cfg.BondDenom)

	type row struct {
		name         string
		utxos        []types.UTXORef
		expectedCode uint32
		expectDelta  int64
	}

	tests := []row{
		{
			name: "valid claim: both seeded UTXOs",
			utxos: []types.UTXORef{
				{Txid: s.seedUTXOs[0].Txid, Vout: s.seedUTXOs[0].Vout},
				{Txid: s.seedUTXOs[1].Txid, Vout: s.seedUTXOs[1].Vout},
			},
			expectedCode: 0,
			expectDelta: int64(
				s.seedUTXOs[0].EntitledAmount + s.seedUTXOs[1].EntitledAmount,
			),
		},
		{
			name: "replay: UTXOs already claimed",
			utxos: []types.UTXORef{
				{Txid: s.seedUTXOs[0].Txid, Vout: s.seedUTXOs[0].Vout},
			},
			// no valid claimable UTXOs remain — CheckTx returns ErrInvalidRequest
			expectedCode: 18,
			expectDelta:  0,
		},
	}

	var cumulativeDelta int64
	for _, tc := range tests {
		s.Require().NoError(s.network.WaitForNextBlock())
		s.Run(tc.name, func() {
			msg := s.buildClaimMsg(claimer, tc.utxos)
			resp := s.submitClaim(claimer, msg)
			s.Require().Equalf(tc.expectedCode, resp.Code,
				"unexpected tx code (raw log: %s)", resp.RawLog)

			cumulativeDelta += tc.expectDelta
			postBal := s.queryBalance(claimer, s.cfg.BondDenom)
			s.Require().Equal(
				sdkmath.NewInt(cumulativeDelta).String(),
				postBal.Sub(preBal).String(),
				"cumulative balance delta should match sum of successful claims")
		})
	}
}

// buildClaimMsg signs the claim message with the test BTC key the way a wallet
// would, generates a PLONK proof, and assembles the MsgClaimWithProof for the
// given claimer.
func (s *E2ETestSuite) buildClaimMsg(claimer string, utxos []types.UTXORef) *types.MsgClaimWithProof {
	params, _, err := zktest.SignClaim(s.btcPrivKey, s.cfg.ChainID, s.btcAddress, claimer, "")
	s.Require().NoError(err)

	pubKeyHashSHA256, err := zk.PubKeyHashSHA256(s.btcPrivKey.PubKey().SerializeCompressed())
	s.Require().NoError(err)

	prover := zk.ProverFromSetup(s.setup)
	proofBytes, err := prover.GenerateProof(params)
	s.Require().NoError(err)

	return &types.MsgClaimWithProof{
		Claimer:          claimer,
		Broadcaster:      claimer,
		Utxos:            utxos,
		Proof:            hex.EncodeToString(proofBytes),
		PubKeyHashSha256: hex.EncodeToString(pubKeyHashSHA256[:]),
	}
}

// submitClaim invokes the real `tx qbtc claim-with-proof` CLI command via the
// module's testutil wrapper, then polls for the DeliverTx result. This mirrors
// the SDK pattern: sync-broadcast → CheckTx response if it rejected the tx,
// otherwise the final code.
func (s *E2ETestSuite) submitClaim(from string, msg *types.MsgClaimWithProof) sdk.TxResponse {
	val := s.network.Validators[0]

	args := []string{
		fmt.Sprintf("--%s=%s", flags.FlagFrom, from),
		fmt.Sprintf("--%s=true", flags.FlagSkipConfirmation),
		fmt.Sprintf("--%s=%s", flags.FlagBroadcastMode, flags.BroadcastSync),
		fmt.Sprintf("--%s=%s", flags.FlagChainID, s.cfg.ChainID),
		fmt.Sprintf("--%s=%d", flags.FlagGas, 1_500_000),
		fmt.Sprintf("--%s=0%s", flags.FlagFees, s.cfg.BondDenom),
	}

	out, err := qbtcclitestutil.MsgClaimWithProofExec(val.ClientCtx, msg, args...)
	s.Require().NoError(err)

	var syncResp sdk.TxResponse
	s.Require().NoError(val.ClientCtx.Codec.UnmarshalJSON(out.Bytes(), &syncResp))
	s.Require().NotEmpty(syncResp.TxHash, "expected a tx hash from sync broadcast")
	if syncResp.Code != 0 {
		// CheckTx turned the claim away; it never reaches a block.
		return syncResp
	}

	resp, err := clitestutil.GetTxResponse(s.network, val.ClientCtx, syncResp.TxHash)
	s.Require().NoError(err)
	return resp
}

// queryBalance returns the claimer's spendable balance for the given denom via
// the bank gRPC query. Returns zero when the account does not yet exist.
func (s *E2ETestSuite) queryBalance(addr, denom string) sdkmath.Int {
	c := banktypes.NewQueryClient(s.network.Validators[0].ClientCtx)
	res, err := c.Balance(context.Background(), &banktypes.QueryBalanceRequest{
		Address: addr,
		Denom:   denom,
	})
	s.Require().NoError(err)
	if res.Balance == nil {
		return sdkmath.ZeroInt()
	}
	return res.Balance.Amount
}

// TestFirstTimeClaim claims to a destination that has no account on chain,
// signed by an existing broadcaster key as the proof service does, with no fee
// and the CLI's default gas. A claim with a bogus proof is turned away by
// CheckTx and never reaches a block.
func (s *E2ETestSuite) TestFirstTimeClaim() {
	val := s.network.Validators[0]
	broadcaster := val.Address.String()
	seed := s.seedUTXOs[2]
	utxos := []types.UTXORef{{Txid: seed.Txid, Vout: seed.Vout}}
	defaultGasArgs := []string{
		fmt.Sprintf("--%s=%s", flags.FlagFrom, broadcaster),
		fmt.Sprintf("--%s=true", flags.FlagSkipConfirmation),
		fmt.Sprintf("--%s=%s", flags.FlagBroadcastMode, flags.BroadcastSync),
		fmt.Sprintf("--%s=%s", flags.FlagChainID, s.cfg.ChainID),
		fmt.Sprintf("--%s=0%s", flags.FlagFees, s.cfg.BondDenom),
	}
	broadcast := func(msg *types.MsgClaimWithProof) sdk.TxResponse {
		out, err := qbtcclitestutil.MsgClaimWithProofExec(val.ClientCtx, msg, defaultGasArgs...)
		s.Require().NoError(err)
		var resp sdk.TxResponse
		s.Require().NoError(val.ClientCtx.Codec.UnmarshalJSON(out.Bytes(), &resp))
		return resp
	}

	s.Run("bogus proof is rejected by CheckTx", func() {
		s.Require().NoError(s.network.WaitForNextBlock())
		msg := s.buildClaimMsg(sdk.AccAddress([]byte("bogus-proof-destination")).String(), utxos)
		msg.Broadcaster = broadcaster
		msg.Proof = hex.EncodeToString(zktest.WellFormedProof(zk.ClaimCircuitNbCommitments))
		resp := broadcast(msg)
		s.Require().NotZero(resp.Code, "a bogus proof must not enter the mempool")
		s.Require().Contains(resp.RawLog, "proof verification failed")
	})

	s.Run("destination without an account, no fee, default gas", func() {
		s.Require().NoError(s.network.WaitForNextBlock())
		claimer := sdk.AccAddress([]byte("first-time-claimer-dest")).String()
		_, err := authtypes.NewQueryClient(val.ClientCtx).Account(context.Background(), &authtypes.QueryAccountRequest{Address: claimer})
		s.Require().Error(err, "the destination must not have an account yet")

		msg := s.buildClaimMsg(claimer, utxos)
		msg.Broadcaster = broadcaster
		sync := broadcast(msg)
		s.Require().Zero(sync.Code, "CheckTx: %s", sync.RawLog)
		resp, err := clitestutil.GetTxResponse(s.network, val.ClientCtx, sync.TxHash)
		s.Require().NoError(err)
		s.Require().Zero(resp.Code, "DeliverTx: %s", resp.RawLog)
		s.Require().Equal(sdkmath.NewIntFromUint64(seed.EntitledAmount).String(), s.queryBalance(claimer, s.cfg.BondDenom).String())
	})
}
