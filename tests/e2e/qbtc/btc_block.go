package qbtc

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/cometbft/cometbft/privval"
	"github.com/cosmos/cosmos-sdk/client/flags"
	clitestutil "github.com/cosmos/cosmos-sdk/testutil/cli"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authzcli "github.com/cosmos/cosmos-sdk/x/authz/client/cli"

	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// TestMsgBtcBlockViaAuthzExecRejected sends a correctly attested MsgBtcBlock
// nested in an authz MsgExec where the sender is both granter and grantee
// (authz needs no grant for that). The ante handler only sees the MsgExec, so
// the block handler itself has to reject the inner message.
func (s *E2ETestSuite) TestMsgBtcBlockViaAuthzExecRejected() {
	val := s.network.Validators[0]
	q := types.NewQueryClient(val.ClientCtx)

	before, err := q.LastProcessedBlock(context.Background(), &types.QueryLastProcessedBlockRequest{})
	s.Require().NoError(err)

	const (
		height   = 900000
		coinbase = "cbcb000000000000000000000000000000000000000000000000000000000001"
	)
	content, err := json.Marshal(btcjson.GetBlockVerboseTxResult{
		Hash:   fmt.Sprintf("%064x", height),
		Height: height,
		Tx: []btcjson.TxRawResult{{
			Txid: coinbase,
			Vin:  []btcjson.Vin{{Coinbase: "03a0bb0d"}},
			Vout: []btcjson.Vout{{
				Value:        btcutil.Amount(312_500_000).ToBTC(),
				N:            0,
				ScriptPubKey: btcjson.ScriptPubKeyResult{Type: "pubkeyhash", Address: s.btcAddress},
			}},
		}},
	})
	s.Require().NoError(err)
	compressed, err := types.GzipDeterministic(content, gzip.BestCompression)
	s.Require().NoError(err)

	// Attest with the only validator's consensus key, so the attestation check
	// alone would accept the block.
	cmtCfg := val.GetCtx().Config
	pv := privval.LoadFilePV(cmtCfg.PrivValidatorKeyFile(), cmtCfg.PrivValidatorStateFile())
	sig, err := pv.Key.PrivKey.Sign(compressed)
	s.Require().NoError(err)

	msg := &types.MsgBtcBlock{
		Height:       height,
		Hash:         fmt.Sprintf("%064x", height),
		BlockContent: compressed,
		Attestations: []*types.Attestation{{
			Address:   sdk.ConsAddress(pv.Key.PubKey.Address()).String(),
			Signature: sig,
		}},
		Signer: val.Address.String(),
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
	_, err = q.UTXO(context.Background(), &types.QueryUTXORequest{Txid: coinbase, Vout: 0})
	s.Require().Error(err, "the block's coinbase output must not exist")
}
