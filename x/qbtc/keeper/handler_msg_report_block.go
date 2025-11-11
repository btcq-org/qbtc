package keeper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"cosmossdk.io/collections"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/btcsuite/btcd/btcjson"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerror "github.com/cosmos/cosmos-sdk/types/errors"
)

func (s *msgServer) SetMsgReportBlock(ctx context.Context, msg *types.MsgBtcBlock) (*types.MsgEmpty, error) {
	if err := msg.ValidateBasic(); err != nil {
		return nil, sdkerror.ErrInvalidRequest.Wrap("invalid MsgBtcBlock")
	}
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	// unzip block content
	rawBlockContent, err := types.GzipUnzip(msg.BlockContent)
	if err != nil {
		return nil, sdkerror.ErrInvalidRequest.Wrap("failed to unzip block content")
	}
	var block btcjson.GetBlockVerboseTxResult
	if err := json.Unmarshal(rawBlockContent, &block); err != nil {
		return nil, sdkerror.ErrInvalidRequest.Wrap("failed to unmarshal block content")
	}
	// process the reported block
	for _, tx := range block.Tx {
		if err := s.processTransaction(sdkCtx, tx); err != nil {
			sdkCtx.Logger().Error("failed to process transaction", "txid", tx.Txid, "error", err)
			return nil, sdkerror.ErrUnknownRequest.Wrapf("failed to process transaction %s: %v", tx.Txid, err)
		}
	}
	return &types.MsgEmpty{}, nil
}

func (s *msgServer) processTransaction(ctx sdk.Context, tx btcjson.TxRawResult) error {
	totalClamable, totalInput, hasClaimed := s.processVIn(ctx, tx.Vin)

	totalOutput := uint64(0)
	for _, out := range tx.Vout {
		if out.Value == 0 {
			continue
		}
		totalOutput += uint64(out.Value * 1e8)
	}
	// calculate the transaction fee
	fee := totalInput - totalOutput
	totalClamable = totalClamable - fee
	if totalClamable > 0 {
		if err := s.processVOuts(ctx, tx.Vout, tx.Txid, totalClamable, hasClaimed); err != nil {
			return err
		}
	}
	return nil
}
func getUTXOKey(txID string, vOut uint32) string {
	return fmt.Sprintf("%s-%d", txID, vOut)
}

// processVIn remove the UTXOs from the key value store since it has been spent , can't be claim anymore
// return the total amount that can be claimed
func (s *msgServer) processVIn(ctx sdk.Context, ins []btcjson.Vin) (uint64, uint64, bool) {
	totalClaimableAmount := uint64(0)
	totalInputAmount := uint64(0)
	hasClaimed := false
	for _, in := range ins {
		key := getUTXOKey(in.Txid, in.Vout)
		existingUtxo, err := s.k.Utxoes.Get(ctx, key)
		if err != nil {
			if !errors.Is(err, collections.ErrNotFound) {
				ctx.Logger().Error("failed to get UTXO", "key", key, "error", err)
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
			ctx.Logger().Error("failed to delete UTXO", "key", key, "error", err)
			continue
		}
	}
	return totalClaimableAmount, totalInputAmount, hasClaimed
}

func (s *msgServer) processVOuts(ctx sdk.Context, outs []btcjson.Vout, txid string, totalClaimableAmount uint64, hasClaim bool) error {
	totalLegalOutput := 0
	for _, out := range outs {
		if out.Value == 0 {
			continue
		}
		totalLegalOutput += 1
	}
	for _, out := range outs {
		if out.Value == 0 {
			continue
		}
		entitleAmount := uint64(out.Value * 1e8)
		if hasClaim {
			entitleAmount = totalClaimableAmount / uint64(totalLegalOutput)
		}
		utxo := types.UTXO{
			Txid:           txid,
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
