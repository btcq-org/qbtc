package keeper

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"slices"
	"strings"
	"time"

	"cosmossdk.io/collections"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/cosmos/cosmos-sdk/telemetry"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerror "github.com/cosmos/cosmos-sdk/types/errors"
)

// SetMsgReportBlock processes the reported Bitcoin blocks. The message is
// atomic: if any block is rejected, none is processed.
func (s *msgServer) SetMsgReportBlock(ctx context.Context, msg *types.MsgBtcBlock) (*types.MsgEmpty, error) {
	defer telemetry.MeasureSince(time.Now(), "msg_report_block")

	sdkCtx := sdk.UnwrapSDKContext(ctx)
	// MsgBtcBlock may only come from the block proposer's injection path. The
	// ante handler only sees top-level messages, so a message nested in authz
	// MsgExec, a wasm contract or an ICA packet reaches this handler directly;
	// on all of those paths the signer is an account the sender controls.
	if msg.Signer != types.EBifrostSignerAddress {
		return nil, sdkerror.ErrUnauthorized.Wrap("MsgBtcBlock is only accepted from the block proposer's injection path")
	}
	if !VoteExtensionsEnabled(sdkCtx) {
		return nil, sdkerror.ErrInvalidRequest.Wrap("MsgBtcBlock needs vote extensions, which are not enabled")
	}
	if err := msg.ValidateBasic(); err != nil {
		return nil, sdkerror.ErrInvalidRequest.Wrap("invalid MsgBtcBlock")
	}
	// The blocks must be attested in the previous block's vote extensions by
	// validators with more than 2/3 of the voting power.
	if err := s.k.ValidateBtcBlockVotes(sdkCtx, msg); err != nil {
		return nil, sdkerror.ErrUnauthorized.Wrap(err.Error())
	}

	cacheContext, writeCache := sdkCtx.CacheContext()
	for _, block := range msg.Blocks {
		lastProcessedBlock, err := s.k.GetLastProcessedBlock(cacheContext)
		if err != nil {
			return nil, sdkerror.ErrUnknownRequest.Wrapf("failed to get last processed block height: %v", err)
		}
		if block.Height != lastProcessedBlock+1 {
			return nil, sdkerror.ErrInvalidRequest.Wrapf("block height %d is not the next block height %d", block.Height, lastProcessedBlock+1)
		}
		if err := s.processBtcBlock(cacheContext, block); err != nil {
			return nil, err
		}
	}

	// write the cache context to the main context if we reach here without error
	writeCache()
	return &types.MsgEmpty{}, nil
}

// processBtcBlock verifies one Bitcoin block against the stored tip and
// applies it to ctx: its transactions, the last processed height and the new
// tip. ctx is a cache context that the caller discards on error.
func (s *msgServer) processBtcBlock(ctx sdk.Context, block *types.BtcBlock) error {
	_, commit, err := types.DecodeBtcBlockContent(block.BlockContent)
	if err != nil {
		return sdkerror.ErrInvalidRequest.Wrapf("invalid block content: %v", err)
	}
	header, txs, err := types.ParseBtcBlockCommit(commit)
	if err != nil {
		return sdkerror.ErrInvalidRequest.Wrapf("invalid block content: %v", err)
	}
	params := s.k.btcParams
	tip, err := s.k.getBtcTip(ctx)
	if err != nil {
		return sdkerror.ErrInvalidRequest.Wrapf("cannot accept block %d: %v", block.Height, err)
	}
	// The header must hash to block.Hash, extend the stored tip with valid proof
	// of work, and commit (merkle root) to exactly these transactions.
	txids, err := verifyBtcBlock(params, tip, block.Height, block.Hash, header, txs)
	if err != nil {
		return sdkerror.ErrInvalidRequest.Wrapf("invalid block %d: %v", block.Height, err)
	}

	claimTxs := make([]int, 0)
	totalFee := uint64(0)
	// process the reported block; txs[0] is the coinbase, processed last because
	// it needs the block's total fee
	for i := 1; i < len(txs); i++ {
		tx, txid := txs[i], txids[i].String()
		// check if it is a claim transaction , need to check it before the transaction is processed
		// because utxo that has been spent will be removed from the store, so we can't check it after processing the transaction
		if s.isClaimTx(ctx, params, tx) {
			claimTxs = append(claimTxs, i)
		}
		fee, err := s.processTransaction(ctx, params, tx, txid, block.Height)
		if err != nil {
			ctx.Logger().Error("failed to process transaction", "txid", txid, "error", err)
			return sdkerror.ErrUnknownRequest.Wrapf("failed to process transaction %s: %v", txid, err)
		}
		totalFee += fee
	}
	coinbaseTxid := txids[0].String()
	if err := s.processCoinbaseVOuts(ctx, params, txs[0].TxOut, coinbaseTxid, totalFee, block.Height); err != nil {
		ctx.Logger().Error("failed to process coinbase transaction", "txid", coinbaseTxid, "error", err)
		return sdkerror.ErrUnknownRequest.Wrapf("failed to process coinbase transaction %s: %v", coinbaseTxid, err)
	}
	for _, i := range claimTxs {
		if err := s.processClaimTx(ctx, txs[i], txids[i].String()); err != nil {
			// if we failed to process claim tx, just log the error and continue
			ctx.Logger().Error("failed to process claim transaction", "txid", txids[i].String(), "error", err)
			continue
		}
	}

	// store last block processed height and the new tip
	if err := s.k.LastProcessedBlock.Set(ctx, block.Height); err != nil {
		ctx.Logger().Error("failed to set last processed block height", "height", block.Height, "error", err)
		return sdkerror.ErrUnknownRequest.Wrapf("failed to set last processed block height: %v", err)
	}
	if err := s.k.setBtcTip(ctx, params, block.Height, header); err != nil {
		return sdkerror.ErrUnknownRequest.Wrapf("failed to set btc tip: %v", err)
	}
	ctx.Logger().Info("btc block processed", "height", block.Height, "hash", block.Hash)

	// Record metrics
	telemetry.IncrCounter(1, types.ModuleName, "blocks_processed")
	telemetry.SetGauge(float32(block.Height), types.ModuleName, "last_processed_block_height")
	telemetry.SetGauge(float32(len(txs)), types.ModuleName, "block_tx_count")
	telemetry.SetGauge(float32(totalFee), types.ModuleName, "block_total_fee")
	return nil
}

// outputAmount returns the value of a transaction output in satoshis.
func outputAmount(out *wire.TxOut) (uint64, error) {
	if out.Value < 0 {
		return 0, fmt.Errorf("negative output value %d", out.Value)
	}
	return uint64(out.Value), nil
}

// scriptPubKey describes an output script the way Bitcoin Core's getblock
// does: the script hex, its class name, and an address only for the classes
// Core gives one (not bare public keys or multisig, which have no address).
func scriptPubKey(params *chaincfg.Params, pkScript []byte) *types.ScriptPubKeyResult {
	class, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript, params)
	result := &types.ScriptPubKeyResult{
		Hex:  hex.EncodeToString(pkScript),
		Type: class.String(),
	}
	if err != nil {
		result.Type = txscript.NonStandardTy.String()
		return result
	}
	switch class {
	case txscript.PubKeyHashTy, txscript.ScriptHashTy, txscript.WitnessV0PubKeyHashTy,
		txscript.WitnessV0ScriptHashTy, txscript.WitnessV1TaprootTy:
		if len(addrs) == 1 {
			result.Address = addrs[0].EncodeAddress()
		}
	}
	return result
}

func (s *msgServer) processTransaction(ctx sdk.Context, params *chaincfg.Params, tx *wire.MsgTx, txid string, blockHeight uint64) (uint64, error) {
	defer telemetry.MeasureSince(time.Now(), "process_transaction")
	fee := uint64(0)
	totalClaimable, totalInput, err := s.processVIn(ctx, tx.TxIn)
	if err != nil {
		return fee, err
	}
	totalOutput := uint64(0)
	for _, out := range tx.TxOut {
		amount, err := outputAmount(out)
		if err != nil {
			return fee, err
		}
		totalOutput += amount
	}
	if totalInput > 0 && totalInput > totalOutput {
		// calculate the transaction fee
		fee = totalInput - totalOutput
		if totalClaimable > fee {
			totalClaimable = totalClaimable - fee
		} else {
			totalClaimable = 0
		}
	}
	if err := s.processVOuts(ctx, params, tx.TxOut, txid, totalClaimable, totalOutput, blockHeight); err != nil {
		return fee, err
	}

	return fee, nil
}

const claimPrefix = "claim:"

func (s *msgServer) isClaimTx(ctx sdk.Context, params *chaincfg.Params, tx *wire.MsgTx) bool {
	defer telemetry.MeasureSince(time.Now(), "is_claim_tx")
	// ignore if vOut length is not 2
	if len(tx.TxOut) != 2 {
		return false
	}
	memo := getClaimMemo(tx.TxOut)
	// no claim memo found
	if memo == "" {
		return false
	}
	isSentToItself, err := s.hasUtxoSendToItself(ctx, params, tx)
	if err != nil {
		return false
	}
	if !isSentToItself {
		// only process the claim tx that is sent to itself
		return false
	}
	// make sure the memo address is a valid QBTC address
	_, err = sdk.AccAddressFromBech32(memo)
	if err != nil {
		ctx.Logger().Error("invalid qbtc address in claim memo", "memo", memo, "error", err)
		return false
	}
	return true
}

func (s *msgServer) processClaimTx(ctx sdk.Context, tx *wire.MsgTx, txid string) error {
	defer telemetry.MeasureSince(time.Now(), "process_claim_tx")
	// ignore if vOut length is not 2
	if len(tx.TxOut) != 2 {
		return nil
	}
	memo := getClaimMemo(tx.TxOut)
	// no claim memo found
	if memo == "" {
		return nil
	}

	// make sure the memo address is a valid QBTC address
	memoAddr, err := sdk.AccAddressFromBech32(memo)
	if err != nil {
		return fmt.Errorf("%s is an invalid qbtc address,%w", memo, err)
	}

	// create a cache context to process the claim tx atomically
	cacheCtx, writeCache := ctx.CacheContext()
	for n, out := range tx.TxOut {
		if out.Value == 0 {
			continue
		}
		// Use the unified ClaimUTXO function
		if err := s.k.ClaimUTXO(cacheCtx, txid, uint32(n), memoAddr); err != nil {
			// ClaimUTXO returns nil if already claimed (EntitledAmount == 0)
			// Only fail on actual errors
			ctx.Logger().Error("failed to claim UTXO", "txid", txid, "vout", n, "error", err)
			return fmt.Errorf("fail to claim UTXO: %w", err)
		}
	}
	writeCache()
	return nil
}

func (s *msgServer) hasUtxoSendToItself(ctx sdk.Context, params *chaincfg.Params, tx *wire.MsgTx) (bool, error) {
	defer telemetry.MeasureSince(time.Now(), "has_utxo_send_to_itself")
	var sourceAddress []string
	for _, in := range tx.TxIn {
		// UTXO must already exist since it is used as input
		utxoKey := getUTXOKey(in.PreviousOutPoint.Hash.String(), in.PreviousOutPoint.Index)
		utxo, err := s.k.Utxoes.Get(ctx, utxoKey)
		if err != nil {
			return false, err
		}
		if utxo.ScriptPubKey == nil || utxo.ScriptPubKey.Address == "" {
			// source address unknown, can't confirm the tx is sent to itself
			return false, nil
		}
		sourceAddress = append(sourceAddress, utxo.ScriptPubKey.Address)
	}

	var destAddress []string
	for _, out := range tx.TxOut {
		if out.Value == 0 {
			continue
		}
		destAddress = append(destAddress, scriptPubKey(params, out.PkScript).Address)
	}

	for _, dest := range destAddress {
		found := slices.Contains(sourceAddress, dest)
		if !found {
			return false, nil
		}
	}
	return true, nil
}

// getClaimMemo returns the qbtc address of a "claim:<address>" memo carried as
// the first data push of an OP_RETURN output, or "" if there is none.
func getClaimMemo(outs []*wire.TxOut) string {
	for _, out := range outs {
		if txscript.GetScriptClass(out.PkScript) != txscript.NullDataTy {
			continue
		}
		tokenizer := txscript.MakeScriptTokenizer(0, out.PkScript)
		if !tokenizer.Next() || tokenizer.Opcode() != txscript.OP_RETURN || !tokenizer.Next() {
			continue
		}
		memoStr := strings.ToLower(string(tokenizer.Data()))
		if !strings.HasPrefix(memoStr, claimPrefix) {
			continue
		}
		after, _ := strings.CutPrefix(memoStr, claimPrefix)
		return after
	}
	return ""
}

// getUTXOKey returns the key used to store UTXO in the key value store
func getUTXOKey(txID string, vOut uint32) string {
	return fmt.Sprintf("%s-%d", txID, vOut)
}

// processVIn remove the UTXOs from the key value store since it has been spent , can't be claim anymore
// return the total amount that can be claimed and the total input amount.
// An input that is not in the store contributes nothing to either total.
func (s *msgServer) processVIn(ctx sdk.Context, ins []*wire.TxIn) (uint64, uint64, error) {
	defer telemetry.MeasureSince(time.Now(), "process_vin")
	totalClaimableAmount := uint64(0)
	totalInputAmount := uint64(0)
	for _, in := range ins {
		key := getUTXOKey(in.PreviousOutPoint.Hash.String(), in.PreviousOutPoint.Index)
		existingUtxo, err := s.k.Utxoes.Get(ctx, key)
		if err != nil {
			// UTXO not found, it must have been spent already
			// on production environment , it should not happen, because we will load all unspent UTXOs from bitcoin node at genesis
			if errors.Is(err, collections.ErrNotFound) {
				continue
			}
			return 0, 0, fmt.Errorf("fail to get UTXO %s: %w", key, err)
		}
		totalClaimableAmount = totalClaimableAmount + existingUtxo.EntitledAmount
		totalInputAmount = totalInputAmount + existingUtxo.Amount
		// delete the UTXO since it has been spent
		if err := s.k.Utxoes.Remove(ctx, key); err != nil {
			return 0, 0, fmt.Errorf("fail to delete UTXO,error: %w", err)
		}
	}
	return totalClaimableAmount, totalInputAmount, nil
}

// proportionalEntitlement returns totalClaimable * amount / totalOutput, rounded down.
// totalClaimable is capped at totalOutput, so the result never exceeds amount and
// the 128-bit quotient always fits in uint64.
func proportionalEntitlement(totalClaimable, amount, totalOutput uint64) uint64 {
	if totalOutput == 0 {
		return 0
	}
	totalClaimable = min(totalClaimable, totalOutput)
	hi, lo := bits.Mul64(totalClaimable, amount)
	quo, _ := bits.Div64(hi, lo, totalOutput)
	return quo
}

func (s *msgServer) processVOuts(ctx sdk.Context,
	params *chaincfg.Params,
	outs []*wire.TxOut,
	txID string,
	totalClaimableAmount uint64,
	totalOutputAmount uint64,
	blockHeight uint64) error {
	defer telemetry.MeasureSince(time.Now(), "process_vout")
	for n, out := range outs {
		if out.Value == 0 {
			continue
		}
		amount, err := outputAmount(out)
		if err != nil {
			return err
		}
		// each output can claim an amount proportional to its value, so the outputs together
		// never get more than the inputs had. When every input is fully entitled, the claimable
		// total equals the output total and each output gets its full value.
		entitleAmount := proportionalEntitlement(totalClaimableAmount, amount, totalOutputAmount)
		utxo := types.UTXO{
			Txid:           txID,
			Vout:           uint32(n),
			Amount:         amount,
			EntitledAmount: entitleAmount,
			ScriptPubKey:   scriptPubKey(params, out.PkScript),
			BlockHeight:    blockHeight,
		}
		if err := s.setNewUTXO(ctx, utxo); err != nil {
			return err
		}
	}
	return nil
}

// setNewUTXO stores a UTXO created by a block. A record with the same key must
// not exist: overwriting one would reset its entitlement, and it can only exist
// if the same outputs are processed twice.
func (s *msgServer) setNewUTXO(ctx sdk.Context, utxo types.UTXO) error {
	key := utxo.GetKey()
	exists, err := s.k.Utxoes.Has(ctx, key)
	if err != nil {
		return fmt.Errorf("fail to check UTXO %s: %w", key, err)
	}
	if exists {
		return fmt.Errorf("UTXO %s already exists", key)
	}
	if err := s.k.Utxoes.Set(ctx, key, utxo); err != nil {
		ctx.Logger().Error("failed to save UTXO", "key", key, "error", err)
		return fmt.Errorf("fail to save UTXO,error: %w", err)
	}
	return nil
}

func (s *msgServer) processCoinbaseVOuts(ctx sdk.Context,
	params *chaincfg.Params,
	outs []*wire.TxOut,
	txID string,
	totalFee uint64,
	blockHeight uint64) error {
	defer telemetry.MeasureSince(time.Now(), "process_coinbase_vout")
	for n, out := range outs {
		if out.Value == 0 {
			continue
		}

		amount, err := outputAmount(out)
		if err != nil {
			return err
		}
		entitleAmount := amount
		if entitleAmount > totalFee {
			entitleAmount = entitleAmount - totalFee
		}
		utxo := types.UTXO{
			Txid:           txID,
			Vout:           uint32(n),
			Amount:         amount,
			EntitledAmount: entitleAmount,
			ScriptPubKey:   scriptPubKey(params, out.PkScript),
			BlockHeight:    blockHeight,
		}
		if err := s.setNewUTXO(ctx, utxo); err != nil {
			return err
		}
	}
	return nil
}
