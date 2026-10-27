//go:build vetest_malicious

package abci

import (
	"bytes"
	"os"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// mutateInjectedMsg makes this validator propose a bad MsgBtcBlock when
// QBTC_VETEST_MALICIOUS is set, to test that the other validators reject it:
//   - "forge": the first block with altered content (one more coinbase output)
//   - "noevidence": the blocks without the extended commit
//
// This file is only compiled with the vetest_malicious build tag.
func mutateInjectedMsg(ctx sdk.Context, msg *types.MsgBtcBlock) *types.MsgBtcBlock {
	mode := os.Getenv("QBTC_VETEST_MALICIOUS")
	if mode == "" || len(msg.Blocks) == 0 {
		return msg
	}
	bad := *msg
	switch mode {
	case "forge":
		block := *msg.Blocks[0]
		_, commit, err := types.DecodeBtcBlockContent(block.BlockContent)
		if err != nil {
			return msg
		}
		_, txs, err := types.ParseBtcBlockCommit(commit)
		if err != nil || len(txs) == 0 || len(txs[0].TxOut) == 0 {
			return msg
		}
		txs[0].AddTxOut(txs[0].TxOut[0])
		forged := &types.BtcBlockCommit{Header: commit.Header}
		for _, tx := range txs {
			var buf bytes.Buffer
			if err := tx.SerializeNoWitness(&buf); err != nil {
				return msg
			}
			forged.Txs = append(forged.Txs, buf.Bytes())
		}
		_, content, err := types.EncodeBtcBlockCommit(forged)
		if err != nil {
			return msg
		}
		block.BlockContent = content
		bad.Blocks = append([]*types.BtcBlock{&block}, msg.Blocks[1:]...)
	case "noevidence":
		bad.ExtendedCommitInfo = nil
	default:
		return msg
	}
	ctx.Logger().Error("VETEST: proposing a malicious btc block message", "mode", mode, "height", msg.Blocks[0].Height)
	return &bad
}
