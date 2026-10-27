package qbtc

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/cosmos/cosmos-sdk/client/flags"
	clitestutil "github.com/cosmos/cosmos-sdk/testutil/cli"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authzcli "github.com/cosmos/cosmos-sdk/x/authz/client/cli"

	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// TestMsgBtcBlockViaAuthzExecRejected sends a well-formed MsgBtcBlock
// nested in an authz MsgExec where the sender is both granter and grantee
// (authz needs no grant for that). The ante handler only sees the MsgExec, so
// the block handler itself has to reject the inner message.
func (s *E2ETestSuite) TestMsgBtcBlockViaAuthzExecRejected() {
	val := s.network.Validators[0]
	q := types.NewQueryClient(val.ClientCtx)

	before, err := q.LastProcessedBlock(context.Background(), &types.QueryLastProcessedBlockRequest{})
	s.Require().NoError(err)

	const height = 900000
	coinbase := wire.NewMsgTx(2)
	coinbase.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{}, wire.MaxPrevOutIndex), []byte{0x03, 0xa0, 0xbb, 0x0d}, nil))
	coinbase.AddTxOut(wire.NewTxOut(312_500_000, []byte{0x51}))
	block := wire.NewMsgBlock(&wire.BlockHeader{Version: 4, Bits: 0x207fffff})
	s.Require().NoError(block.AddTransaction(coinbase))
	commit, err := types.NewBtcBlockCommit(block)
	s.Require().NoError(err)
	_, content, err := types.EncodeBtcBlockCommit(commit)
	s.Require().NoError(err)

	// A well-formed message, so that only the signer check can reject it. The
	// extended commit is a placeholder: the handler rejects the signer first.
	msg := &types.MsgBtcBlock{
		Blocks: []*types.BtcBlock{{
			Height:       height,
			Hash:         block.BlockHash().String(),
			BlockContent: content,
		}},
		ExtendedCommitInfo: []byte{0x01},
		Signer:             val.Address.String(),
	}

	// authz exec reads the inner messages from an unsigned tx file.
	txBuilder := val.ClientCtx.TxConfig.NewTxBuilder()
	s.Require().NoError(txBuilder.SetMsgs(msg))
	txJSON, err := val.ClientCtx.TxConfig.TxJSONEncoder()(txBuilder.GetTx())
	s.Require().NoError(err)
	txFile := filepath.Join(s.T().TempDir(), "inner.json")
	s.Require().NoError(os.WriteFile(txFile, txJSON, 0o600))

	out, err := clitestutil.ExecTestCLICmd(val.ClientCtx, authzcli.NewCmdExecAuthorization(), []string{
		txFile,
		fmt.Sprintf("--%s=%s", flags.FlagFrom, val.Address.String()),
		fmt.Sprintf("--%s=true", flags.FlagSkipConfirmation),
		fmt.Sprintf("--%s=%s", flags.FlagBroadcastMode, flags.BroadcastSync),
		fmt.Sprintf("--%s=%s", flags.FlagChainID, s.cfg.ChainID),
		fmt.Sprintf("--%s=%d", flags.FlagGas, 2_000_000),
		fmt.Sprintf("--%s=1000%s", flags.FlagFees, s.cfg.BondDenom),
	})
	s.Require().NoError(err)

	var syncResp sdk.TxResponse
	s.Require().NoError(val.ClientCtx.Codec.UnmarshalJSON(out.Bytes(), &syncResp))
	s.Require().Zero(syncResp.Code, "MsgExec should pass CheckTx: %s", syncResp.RawLog)

	resp, err := clitestutil.GetTxResponse(s.network, val.ClientCtx, syncResp.TxHash)
	s.Require().NoError(err)
	s.Require().NotZero(resp.Code, "nested MsgBtcBlock must fail")
	s.Require().Contains(resp.RawLog, "injection path")

	after, err := q.LastProcessedBlock(context.Background(), &types.QueryLastProcessedBlockRequest{})
	s.Require().NoError(err)
	s.Require().Equal(before.Height, after.Height)
	_, err = q.UTXO(context.Background(), &types.QueryUTXORequest{Txid: coinbase.TxHash().String(), Vout: 0})
	s.Require().Error(err, "the block's coinbase output must not exist")
}
