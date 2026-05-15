package qbtc

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"

	sdkmath "cosmossdk.io/math"

	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/cosmos/cosmos-sdk/client/flags"
	clitestutil "github.com/cosmos/cosmos-sdk/testutil/cli"
	sdk "github.com/cosmos/cosmos-sdk/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"

	qbtcclitestutil "github.com/btcq-org/qbtc/x/qbtc/client/testutil"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/btcq-org/qbtc/x/qbtc/zk"
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
			// no valid claimable UTXOs remain — handler returns ErrInvalidRequest
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

// buildClaimMsg signs the binding message with the test BTC key, generates a
// PLONK proof, and assembles the MsgClaimWithProof for the given claimer.
func (s *E2ETestSuite) buildClaimMsg(claimer string, utxos []types.UTXORef) *types.MsgClaimWithProof {
	qbtcAddressHash := zk.HashQBTCAddress(claimer)
	chainIDHash := zk.ComputeChainIDHash(s.cfg.ChainID)
	messageHash := zk.ComputeClaimMessage(s.addressHash, qbtcAddressHash, chainIDHash)

	// TSS-equivalent ECDSA signature over the binding message. Read the
	// scalars straight off the signature object — going through Serialize +
	// hand-rolled DER parsing would risk a panic on malformed input.
	sig := ecdsa.Sign(s.btcPrivKey, messageHash[:])
	rScalar, sScalar := sig.R(), sig.S()
	rBytes, sBytes := rScalar.Bytes(), sScalar.Bytes()
	sigR := new(big.Int).SetBytes(rBytes[:])
	sigS := new(big.Int).SetBytes(sBytes[:])

	pubKey := s.btcPrivKey.PubKey()
	pubKeyHashSHA256, err := zk.PubKeyHashSHA256(pubKey.SerializeCompressed())
	s.Require().NoError(err)

	prover := zk.ProverFromSetup(s.setup)
	proofBytes, err := prover.GenerateProof(zk.ProofParams{
		SignatureR:  sigR,
		SignatureS:  sigS,
		PublicKeyX:  pubKey.X(),
		PublicKeyY:  pubKey.Y(),
		MessageHash: messageHash,
	})
	s.Require().NoError(err)

	return &types.MsgClaimWithProof{
		Claimer:          claimer,
		Broadcaster:      claimer,
		Utxos:            utxos,
		Proof:            hex.EncodeToString(proofBytes),
		MessageHash:      hex.EncodeToString(messageHash[:]),
		AddressHash:      hex.EncodeToString(s.addressHash[:]),
		PubKeyHashSha256: hex.EncodeToString(pubKeyHashSHA256[:]),
		QbtcAddressHash:  hex.EncodeToString(qbtcAddressHash[:]),
	}
}

// submitClaim invokes the real `tx qbtc claim-with-proof` CLI command via the
// module's testutil wrapper, then polls for the DeliverTx result. This mirrors
// the SDK pattern: sync-broadcast → assert CheckTx accepted → query final code.
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

