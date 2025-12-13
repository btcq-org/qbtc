package keeper

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"cosmossdk.io/collections"
	"cosmossdk.io/math"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/btcsuite/btcd/btcjson"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerror "github.com/cosmos/cosmos-sdk/types/errors"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

func (s *msgServer) ValidateMsgBtcBlockAttestation(ctx sdk.Context, msg *types.MsgBtcBlock) error {
	validPower := math.ZeroInt()
	processedValidator := make(map[string]bool, len(msg.Attestations))
	validators, err := s.k.stakingKeeper.GetBondedValidatorsByPower(ctx)
	if err != nil {
		return sdkerror.ErrUnknownRequest.Wrapf("failed to get bonded validators by power: %v", err)
	}
	validatorsByConsAddr := make(map[string]stakingtypes.Validator, len(validators))
	for _, validator := range validators {
		pubKey, err := validator.ConsPubKey()
		if err != nil {
			ctx.Logger().Error("failed to get consensus address for validator", "address", validator.GetOperator(), "error", err)
			continue
		}

		consAddr := sdk.ConsAddress(pubKey.Address())
		validatorsByConsAddr[consAddr.String()] = validator

	}
	for _, attestation := range msg.Attestations {
		if processedValidator[attestation.Address] {
			// skip duplicate attestation from the same validator
			continue
		}
		val, found := validatorsByConsAddr[attestation.Address]
		if !found {
			ctx.Logger().Error("validator not found or not bonded", "address", attestation.Address)
			continue
		}
		publicKey, err := val.ConsPubKey()
		if err != nil {
			ctx.Logger().Error("failed to get consensus public key for validator", "address", attestation.Address, "error", err)
			continue
		}
		if publicKey.VerifySignature(msg.BlockContent, attestation.Signature) {
			validPower = validPower.Add(math.NewInt(val.ConsensusPower(s.k.stakingKeeper.PowerReduction(ctx))))
		}
		processedValidator[attestation.Address] = true
	}
	totalPower, err := s.k.stakingKeeper.GetLastTotalPower(ctx)
	if err != nil {
		return sdkerror.ErrUnknownRequest.Wrapf("failed to get total staking power: %v", err)
	}
	// require more than 2/3 of total staking power to attest the block
	requiredPower := totalPower.Mul(math.NewInt(2)).Quo(math.NewInt(3))
	if validPower.LTE(requiredPower) {
		return sdkerror.ErrUnauthorized.Wrapf("insufficient attestation power: %s, required: %s", validPower.String(), requiredPower.String())
	}
	return nil
}

// SetMsgReportBlock processes a reported Bitcoin block.
func (s *msgServer) SetMsgReportBlock(ctx context.Context, msg *types.MsgBtcBlock) (*types.MsgEmpty, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	lastProcessedBlock, err := s.k.GetLastProcessedBlock(ctx)
	if err != nil {
		return nil, sdkerror.ErrUnknownRequest.Wrapf("failed to get last processed block height: %v", err)
	}
	sdkCtx.Logger().Info("received MsgReportBlock", "height", msg.Height, "hash", msg.Hash, "lastProcessedBlock", lastProcessedBlock)
	// check if the block height is the next block height
	if msg.Height != lastProcessedBlock+1 && msg.Height != lastProcessedBlock && lastProcessedBlock != 0 {
		sdkCtx.Logger().Error("block height is not the next block height - ignore", "reportedHeight", msg.Height, "lastProcessedBlock", lastProcessedBlock)
		return &types.MsgEmpty{}, nil
	}

	if err := msg.ValidateBasic(); err != nil {
		return nil, sdkerror.ErrInvalidRequest.Wrap("invalid MsgBtcBlock")
	}

	if err := s.ValidateMsgBtcBlockAttestation(sdkCtx, msg); err != nil {
		return nil, err
	}
	// unzip block content
	rawBlockContent, err := types.GzipUnzip(msg.BlockContent)
	if err != nil {
		return nil, sdkerror.ErrInvalidRequest.Wrap("failed to unzip block content")
	}
	var block btcjson.GetBlockVerboseTxResult
	if err := json.Unmarshal(rawBlockContent, &block); err != nil {
		return nil, sdkerror.ErrInvalidRequest.Wrap("failed to unmarshal block content")
	}
	cacheContext, writeCache := sdkCtx.CacheContext()
	claimTxIds := make([]string, 0)
	totalFee := uint64(0)
	var coinBaseTx *btcjson.TxRawResult
	// process the reported block
	for _, tx := range block.Tx {
		// check if it is a claim transaction , need to check it before the transaction is processed
		// because utxo that has been spent will be removed from the store, so we can't check it after processing the transaction
		if s.isClaimTx(cacheContext, tx) {
			claimTxIds = append(claimTxIds, tx.Txid)
		}

		if len(tx.Vin) > 0 && tx.Vin[0].IsCoinBase() {
			// coinbase transaction , process it later, need to calculate the transaction fee first
			coinBaseTx = &tx
			continue
		}
		fee, err := s.processTransaction(cacheContext, tx)
		if err != nil {
			cacheContext.Logger().Error("failed to process transaction", "txid", tx.Txid, "error", err)
			return nil, sdkerror.ErrUnknownRequest.Wrapf("failed to process transaction %s: %v", tx.Txid, err)
		}
		totalFee += fee
	}
	// update coinbase transaction
	if coinBaseTx != nil {
		if err := s.processCoinbaseVOuts(cacheContext, coinBaseTx.Vout, coinBaseTx.Txid, totalFee); err != nil {
			cacheContext.Logger().Error("failed to process coinbase transaction", "txid", coinBaseTx.Txid, "error", err)
			return nil, sdkerror.ErrUnknownRequest.Wrapf("failed to process coinbase transaction %s: %v", coinBaseTx.Txid, err)
		}
	}
	for _, tx := range block.Tx {
		if !slices.Contains(claimTxIds, tx.Txid) {
			continue
		}
		if err := s.processClaimTx(cacheContext, tx); err != nil {
			// if we failed to process claim tx, just log the error and continue
			cacheContext.Logger().Error("failed to process claim transaction", "txid", tx.Txid, "error", err)
			continue
		}
	}

	// store last block processed height
	err = s.k.LastProcessedBlock.Set(cacheContext, msg.Height)
	if err != nil {
		cacheContext.Logger().Error("failed to set last processed block height", "height", msg.Height, "error", err)
		return nil, sdkerror.ErrUnknownRequest.Wrapf("failed to set last processed block height: %v", err)
	}
	sdkCtx.Logger().Info("processed btc block", "height", msg.Height, "hash", msg.Hash)
	// write the cache context to the main context if we reach here without error
	writeCache()
	return &types.MsgEmpty{}, nil
}

func (s *msgServer) processTransaction(ctx sdk.Context, tx btcjson.TxRawResult) (uint64, error) {
	fee := uint64(0)
	totalClaimable, totalInput, hasClaimed, err := s.processVIn(ctx, tx.Vin)
	if err != nil {
		return fee, err
	}
	totalOutput := uint64(0)
	for _, out := range tx.Vout {
		if out.Value == 0 {
			continue
		}
		totalOutput += uint64(out.Value * 1e8)
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
	if err := s.processVOuts(ctx, tx.Vout, tx.Txid, totalClaimable, hasClaimed, totalOutput); err != nil {
		return fee, err
	}

	return fee, nil
}

const claimPrefix = "claim:"
const nullDataType = "nulldata"

func (s *msgServer) isClaimTx(ctx sdk.Context, tx btcjson.TxRawResult) bool {
	// ignore if vOut length is not 2
	if len(tx.Vout) != 2 {
		return false
	}
	memo := s.getClaimMemo(ctx, tx.Vout)
	// no claim memo found
	if memo == "" {
		return false
	}
	isSentToItself, err := s.hasUtxoSendToItself(ctx, tx)
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

func (s *msgServer) processClaimTx(ctx sdk.Context, tx btcjson.TxRawResult) error {
	// ignore if vOut length is not 2
	if len(tx.Vout) != 2 {
		return nil
	}
	memo := s.getClaimMemo(ctx, tx.Vout)
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
	for _, out := range tx.Vout {
		if out.Value == 0 {
			continue
		}
		// Use the unified ClaimUTXO function
		if err := s.k.ClaimUTXO(cacheCtx, tx.Txid, out.N, memoAddr); err != nil {
			// ClaimUTXO returns nil if already claimed (EntitledAmount == 0)
			// Only fail on actual errors
			ctx.Logger().Error("failed to claim UTXO", "txid", tx.Txid, "vout", out.N, "error", err)
			return fmt.Errorf("fail to claim UTXO: %w", err)
		}
	}
	writeCache()
	return nil
}

func (s *msgServer) hasUtxoSendToItself(ctx sdk.Context, tx btcjson.TxRawResult) (bool, error) {
	var sourceAddress []string
	for _, in := range tx.Vin {
		// if one of the inputs is coinbase , which means newly mined coins, we consider it is not sent to itself
		if in.IsCoinBase() {
			return false, nil
		}

		// UTXO must already exist since it is used as input
		utxoKey := getUTXOKey(in.Txid, in.Vout)
		utxo, err := s.k.Utxoes.Get(ctx, utxoKey)
		if err != nil {
			return false, err
		}
		sourceAddress = append(sourceAddress, utxo.ScriptPubKey.Address)
	}

	var destAddress []string
	for _, out := range tx.Vout {
		if out.Value == 0 {
			continue
		}
		destAddress = append(destAddress, out.ScriptPubKey.Address)
	}

	for _, dest := range destAddress {
		found := slices.Contains(sourceAddress, dest)
		if !found {
			return false, nil
		}
	}
	return true, nil
}

// hasClaimMemo checks if any of the vOuts contains a claim memo
func (s *msgServer) getClaimMemo(ctx sdk.Context, vOuts []btcjson.Vout) string {
	for _, item := range vOuts {
		switch item.ScriptPubKey.Type {
		case nullDataType:
			fields := strings.Fields(item.ScriptPubKey.Asm)
			if len(fields) < 2 || fields[0] != "OP_RETURN" {
				continue
			}
			memo, err := hex.DecodeString(fields[1])
			if err != nil {
				ctx.Logger().Error("failed to decode memo", "error", err)
				continue
			}
			memoStr := strings.ToLower(string(memo))
			if !strings.HasPrefix(memoStr, claimPrefix) {
				continue
			}
			after, _ := strings.CutPrefix(memoStr, claimPrefix)
			return after
		}
	}
	return ""
}

// getUTXOKey returns the key used to store UTXO in the key value store
func getUTXOKey(txID string, vOut uint32) string {
	return fmt.Sprintf("%s-%d", txID, vOut)
}

// processVIn remove the UTXOs from the key value store since it has been spent , can't be claim anymore
// return the total amount that can be claimed
func (s *msgServer) processVIn(ctx sdk.Context, ins []btcjson.Vin) (uint64, uint64, bool, error) {
	totalClaimableAmount := uint64(0)
	totalInputAmount := uint64(0)
	hasClaimed := false
	for _, in := range ins {
		if in.IsCoinBase() {
			continue
		}
		key := getUTXOKey(in.Txid, in.Vout)
		existingUtxo, err := s.k.Utxoes.Get(ctx, key)
		if err != nil {
			// UTXO not found, it must have been spent already
			// on production environment , it should not happen, because we will load all unspent UTXOs from bitcoin node at genesis
			if !errors.Is(err, collections.ErrNotFound) {
				ctx.Logger().Error("failed to get UTXO", "key", key, "error", err)
			} else {
				hasClaimed = true
			}
			continue
		}
		if existingUtxo.EntitledAmount == 0 {
			hasClaimed = true
		}
		totalClaimableAmount = totalClaimableAmount + existingUtxo.EntitledAmount
		totalInputAmount = totalInputAmount + existingUtxo.Amount
		// delete the UTXO since it has been spent
		if err := s.k.Utxoes.Remove(ctx, key); err != nil {
			return 0, 0, false, fmt.Errorf("fail to delete UTXO,error: %w", err)
		}
	}
	return totalClaimableAmount, totalInputAmount, hasClaimed, nil
}

func (s *msgServer) processVOuts(ctx sdk.Context,
	outs []btcjson.Vout,
	txID string,
	totalClaimableAmount uint64,
	hasClaim bool,
	totalOutputAmount uint64) error {
	for _, out := range outs {
		if out.Value == 0 {
			continue
		}
		// when none of the txout has been claimed before, each utxo can claim the same amount as its value
		// when any of the txout has been claimed before, each utxo can claim an amount proportional to its value
		entitleAmount := uint64(out.Value * 1e8)
		if hasClaim {
			entitleAmount = totalClaimableAmount * uint64(out.Value*1e8) / totalOutputAmount
		}
		utxo := types.UTXO{
			Txid:           txID,
			Vout:           out.N,
			Amount:         uint64(out.Value * 1e8),
			EntitledAmount: entitleAmount,
			ScriptPubKey: &types.ScriptPubKeyResult{
				Hex:     out.ScriptPubKey.Hex,
				Type:    out.ScriptPubKey.Type,
				Address: out.ScriptPubKey.Address,
			},
		}
		if err := s.k.Utxoes.Set(ctx, utxo.GetKey(), utxo); err != nil {
			ctx.Logger().Error("failed to save UTXO", "key", utxo.GetKey(), "error", err)
			return fmt.Errorf("fail to save UTXO,error: %w", err)
		}
	}
	return nil
}
func (s *msgServer) processCoinbaseVOuts(ctx sdk.Context,
	outs []btcjson.Vout,
	txID string,
	totalFee uint64) error {
	for _, out := range outs {
		if out.Value == 0 {
			continue
		}

		entitleAmount := uint64(out.Value * 1e8)
		if entitleAmount > totalFee {
			entitleAmount = entitleAmount - totalFee
		}
		utxo := types.UTXO{
			Txid:           txID,
			Vout:           out.N,
			Amount:         uint64(out.Value * 1e8),
			EntitledAmount: entitleAmount,
			ScriptPubKey: &types.ScriptPubKeyResult{
				Hex:     out.ScriptPubKey.Hex,
				Type:    out.ScriptPubKey.Type,
				Address: out.ScriptPubKey.Address,
			},
		}
		if err := s.k.Utxoes.Set(ctx, utxo.GetKey(), utxo); err != nil {
			ctx.Logger().Error("failed to save UTXO", "key", utxo.GetKey(), "error", err)
			return fmt.Errorf("fail to save UTXO,error: %w", err)
		}
	}
	return nil
}
