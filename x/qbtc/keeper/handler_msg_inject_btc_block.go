package keeper

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"cosmossdk.io/collections"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/cosmos/cosmos-sdk/telemetry"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerror "github.com/cosmos/cosmos-sdk/types/errors"
)

// chainParams are the Bitcoin network parameters used to derive human-readable
// addresses from raw scriptPubKeys. Mainnet for production.
var chainParams = &chaincfg.MainNetParams

// InjectBtcBlock applies a vote-extension-attested minimal Bitcoin block delta
// to the UTXO set. It is only ever delivered via proposer injection (enforced
// by the ante handler) and is the replacement for the legacy
// SetMsgReportBlock + gossip-attestation flow.
func (s *msgServer) InjectBtcBlock(ctx context.Context, msg *types.MsgInjectBtcBlock) (*types.MsgEmpty, error) {
	defer telemetry.MeasureSince(time.Now(), "msg_inject_btc_block")

	sdkCtx := sdk.UnwrapSDKContext(ctx)
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}
	delta := msg.Delta
	height := uint64(delta.Height)

	lastProcessedBlock, err := s.k.GetLastProcessedBlock(ctx)
	if err != nil {
		return nil, sdkerror.ErrUnknownRequest.Wrapf("failed to get last processed block height: %v", err)
	}
	// Only the next contiguous block is accepted; anything else is ignored so a
	// stale or out-of-order injection cannot desync the cursor.
	if height != lastProcessedBlock+1 && lastProcessedBlock != 0 {
		sdkCtx.Logger().Error("btc block height is not the next height - ignore", "reportedHeight", height, "lastProcessedBlock", lastProcessedBlock)
		return &types.MsgEmpty{}, nil
	}

	// Authoritative supermajority / integrity check.
	if err := s.k.ValidateInjectedBtcBlock(sdkCtx, msg); err != nil {
		return nil, err
	}

	cacheCtx, writeCache := sdkCtx.CacheContext()
	claimTxIds := make([]string, 0)
	totalFee := uint64(0)
	var coinbaseTx *types.BtcTx

	for i := range delta.Txs {
		tx := delta.Txs[i]
		// Detect claim txs before processing, because their spent inputs are
		// removed from the store during processing.
		if s.isClaimDeltaTx(cacheCtx, tx) {
			claimTxIds = append(claimTxIds, tx.TxidHex())
		}
		if tx.Coinbase {
			coinbaseTx = tx
			continue
		}
		fee, err := s.processDeltaTransaction(cacheCtx, tx, height)
		if err != nil {
			cacheCtx.Logger().Error("failed to process btc tx", "txid", tx.TxidHex(), "error", err)
			return nil, sdkerror.ErrUnknownRequest.Wrapf("failed to process transaction %s: %v", tx.TxidHex(), err)
		}
		totalFee += fee
	}

	if coinbaseTx != nil {
		if err := s.processDeltaCoinbaseVOuts(cacheCtx, coinbaseTx, totalFee, height); err != nil {
			cacheCtx.Logger().Error("failed to process coinbase tx", "txid", coinbaseTx.TxidHex(), "error", err)
			return nil, sdkerror.ErrUnknownRequest.Wrapf("failed to process coinbase transaction %s: %v", coinbaseTx.TxidHex(), err)
		}
	}

	if len(claimTxIds) > 0 {
		for i := range delta.Txs {
			tx := delta.Txs[i]
			if !slices.Contains(claimTxIds, tx.TxidHex()) {
				continue
			}
			if err := s.processDeltaClaimTx(cacheCtx, tx); err != nil {
				cacheCtx.Logger().Error("failed to process claim tx", "txid", tx.TxidHex(), "error", err)
				continue
			}
		}
	}

	if err := s.k.LastProcessedBlock.Set(cacheCtx, height); err != nil {
		return nil, sdkerror.ErrUnknownRequest.Wrapf("failed to set last processed block height: %v", err)
	}

	telemetry.IncrCounter(1, types.ModuleName, "blocks_processed")
	telemetry.SetGauge(float32(height), types.ModuleName, "last_processed_block_height")
	telemetry.SetGauge(float32(len(delta.Txs)), types.ModuleName, "block_tx_count")
	telemetry.SetGauge(float32(totalFee), types.ModuleName, "block_total_fee")

	writeCache()
	sdkCtx.Logger().Info("processed btc block delta", "height", height, "hash", hex.EncodeToString(delta.BlockHash))
	return &types.MsgEmpty{}, nil
}

// deriveScriptInfo derives the script type and human-readable address from a
// raw scriptPubKey. Any unsupported/nonstandard script yields a "nonstandard"
// type and an empty address, mirroring block-explorer behavior.
func deriveScriptInfo(script []byte) (scriptType, address string) {
	class, addrs, _, err := txscript.ExtractPkScriptAddrs(script, chainParams)
	if err != nil {
		return txscript.NonStandardTy.String(), ""
	}
	if len(addrs) > 0 {
		address = addrs[0].EncodeAddress()
	}
	return class.String(), address
}

// getDeltaClaimMemo extracts a lowercase "claim:<addr>" memo from an OP_RETURN
// output, if present.
func getDeltaClaimMemo(outputs []*types.BtcTxOut) string {
	for _, out := range outputs {
		script := out.ScriptPubKey
		if len(script) == 0 || script[0] != txscript.OP_RETURN {
			continue
		}
		pushed, err := txscript.PushedData(script)
		if err != nil || len(pushed) == 0 {
			continue
		}
		memo := strings.ToLower(string(pushed[0]))
		if !strings.HasPrefix(memo, claimPrefix) {
			continue
		}
		return strings.TrimPrefix(memo, claimPrefix)
	}
	return ""
}

func (s *msgServer) isClaimDeltaTx(ctx sdk.Context, tx *types.BtcTx) bool {
	// A claim tx has exactly two outputs: the self-send and the OP_RETURN memo.
	if len(tx.Outputs) != 2 {
		return false
	}
	memo := getDeltaClaimMemo(tx.Outputs)
	if memo == "" {
		return false
	}
	sentToItself, err := s.hasDeltaUtxoSendToItself(ctx, tx)
	if err != nil || !sentToItself {
		return false
	}
	if _, err := sdk.AccAddressFromBech32(memo); err != nil {
		ctx.Logger().Error("invalid qbtc address in claim memo", "memo", memo, "error", err)
		return false
	}
	return true
}

func (s *msgServer) hasDeltaUtxoSendToItself(ctx sdk.Context, tx *types.BtcTx) (bool, error) {
	if tx.Coinbase {
		return false, nil
	}
	var sourceAddrs []string
	for _, in := range tx.Inputs {
		utxo, err := s.k.Utxoes.Get(ctx, getUTXOKey(in.TxidHex(), in.Vout))
		if err != nil {
			return false, err
		}
		if utxo.ScriptPubKey != nil {
			sourceAddrs = append(sourceAddrs, utxo.ScriptPubKey.Address)
		}
	}
	for _, out := range tx.Outputs {
		if out.Value == 0 {
			continue
		}
		_, addr := deriveScriptInfo(out.ScriptPubKey)
		if !slices.Contains(sourceAddrs, addr) {
			return false, nil
		}
	}
	return true, nil
}

func (s *msgServer) processDeltaClaimTx(ctx sdk.Context, tx *types.BtcTx) error {
	if len(tx.Outputs) != 2 {
		return nil
	}
	memo := getDeltaClaimMemo(tx.Outputs)
	if memo == "" {
		return nil
	}
	memoAddr, err := sdk.AccAddressFromBech32(memo)
	if err != nil {
		return fmt.Errorf("%s is an invalid qbtc address: %w", memo, err)
	}
	cacheCtx, writeCache := ctx.CacheContext()
	txid := tx.TxidHex()
	for i, out := range tx.Outputs {
		if out.Value == 0 {
			continue
		}
		if err := s.k.ClaimUTXO(cacheCtx, txid, uint32(i), memoAddr); err != nil {
			ctx.Logger().Error("failed to claim UTXO", "txid", txid, "vout", i, "error", err)
			return fmt.Errorf("fail to claim UTXO: %w", err)
		}
	}
	writeCache()
	return nil
}

func (s *msgServer) processDeltaTransaction(ctx sdk.Context, tx *types.BtcTx, blockHeight uint64) (uint64, error) {
	fee := uint64(0)
	totalClaimable, totalInput, hasClaimed, err := s.processDeltaVIn(ctx, tx.Inputs)
	if err != nil {
		return fee, err
	}
	totalOutput := uint64(0)
	for _, out := range tx.Outputs {
		totalOutput += out.Value
	}
	if totalInput > 0 && totalInput > totalOutput {
		fee = totalInput - totalOutput
		if totalClaimable > fee {
			totalClaimable -= fee
		} else {
			totalClaimable = 0
		}
	}
	if err := s.processDeltaVOuts(ctx, tx, totalClaimable, hasClaimed, totalOutput, blockHeight); err != nil {
		return fee, err
	}
	return fee, nil
}

// processDeltaVIn deletes spent UTXOs and returns the total claimable amount,
// total input amount, and whether any spent input had already been claimed.
func (s *msgServer) processDeltaVIn(ctx sdk.Context, ins []*types.BtcOutpoint) (uint64, uint64, bool, error) {
	totalClaimable := uint64(0)
	totalInput := uint64(0)
	hasClaimed := false
	for _, in := range ins {
		key := getUTXOKey(in.TxidHex(), in.Vout)
		existing, err := s.k.Utxoes.Get(ctx, key)
		if err != nil {
			if !errors.Is(err, collections.ErrNotFound) {
				ctx.Logger().Error("failed to get UTXO", "key", key, "error", err)
			} else {
				hasClaimed = true
			}
			continue
		}
		if existing.EntitledAmount == 0 {
			hasClaimed = true
		}
		totalClaimable += existing.EntitledAmount
		totalInput += existing.Amount
		if err := s.k.Utxoes.Remove(ctx, key); err != nil {
			return 0, 0, false, fmt.Errorf("fail to delete UTXO: %w", err)
		}
	}
	return totalClaimable, totalInput, hasClaimed, nil
}

func (s *msgServer) processDeltaVOuts(ctx sdk.Context, tx *types.BtcTx, totalClaimable uint64, hasClaim bool, totalOutput uint64, blockHeight uint64) error {
	txid := tx.TxidHex()
	for i, out := range tx.Outputs {
		if out.Value == 0 {
			continue
		}
		entitled := out.Value
		if hasClaim && totalOutput > 0 {
			entitled = totalClaimable * out.Value / totalOutput
		}
		if err := s.setDeltaUTXO(ctx, txid, uint32(i), out, entitled, blockHeight); err != nil {
			return err
		}
	}
	return nil
}

func (s *msgServer) processDeltaCoinbaseVOuts(ctx sdk.Context, tx *types.BtcTx, totalFee uint64, blockHeight uint64) error {
	txid := tx.TxidHex()
	for i, out := range tx.Outputs {
		if out.Value == 0 {
			continue
		}
		entitled := out.Value
		if entitled > totalFee {
			entitled -= totalFee
		}
		if err := s.setDeltaUTXO(ctx, txid, uint32(i), out, entitled, blockHeight); err != nil {
			return err
		}
	}
	return nil
}

func (s *msgServer) setDeltaUTXO(ctx sdk.Context, txid string, vout uint32, out *types.BtcTxOut, entitled, blockHeight uint64) error {
	scriptType, address := deriveScriptInfo(out.ScriptPubKey)
	utxo := types.UTXO{
		Txid:           txid,
		Vout:           vout,
		Amount:         out.Value,
		EntitledAmount: entitled,
		ScriptPubKey: &types.ScriptPubKeyResult{
			Hex:     hex.EncodeToString(out.ScriptPubKey),
			Type:    scriptType,
			Address: address,
		},
		BlockHeight: blockHeight,
	}
	if err := s.k.Utxoes.Set(ctx, utxo.GetKey(), utxo); err != nil {
		ctx.Logger().Error("failed to save UTXO", "key", utxo.GetKey(), "error", err)
		return fmt.Errorf("fail to save UTXO: %w", err)
	}
	return nil
}
