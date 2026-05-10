package keeper

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"cosmossdk.io/collections"
	"cosmossdk.io/math"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/cosmos/cosmos-sdk/telemetry"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerror "github.com/cosmos/cosmos-sdk/types/errors"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/cosmos/gogoproto/proto"
)

// ValidateMsgBtcBlockAttestation requires more than 2/3 of bonded staking
// power to have signed proto.Marshal(msg.Commit). The signed payload is the
// canonical serialization of the structured block commit; it covers both the
// header and the slim transaction list.
func (s *msgServer) ValidateMsgBtcBlockAttestation(ctx sdk.Context, msg *types.MsgBtcBlock) error {
	commitBytes, err := proto.Marshal(msg.Commit)
	if err != nil {
		return sdkerror.ErrInvalidRequest.Wrapf("failed to marshal commit: %v", err)
	}
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
		if publicKey.VerifySignature(commitBytes, attestation.Signature) {
			validPower = validPower.Add(math.NewInt(val.ConsensusPower(s.k.stakingKeeper.PowerReduction(ctx))))
		}
		processedValidator[attestation.Address] = true
	}
	totalPower, err := s.k.stakingKeeper.GetLastTotalPower(ctx)
	if err != nil {
		return sdkerror.ErrUnknownRequest.Wrapf("failed to get total staking power: %v", err)
	}
	requiredPower := totalPower.Mul(math.NewInt(2)).Quo(math.NewInt(3))
	if validPower.LTE(requiredPower) {
		return sdkerror.ErrUnauthorized.Wrapf("insufficient attestation power: %s, required: %s", validPower.String(), requiredPower.String())
	}
	return nil
}

// SetMsgReportBlock processes a reported Bitcoin block: it verifies the
// supermajority attestation, anchors the BTC header (PoW + prev-hash + merkle
// root), then walks the slim tx list to spend inputs, mint new UTXOs, and
// settle any claim transactions in the same block.
func (s *msgServer) SetMsgReportBlock(ctx context.Context, msg *types.MsgBtcBlock) (*types.MsgEmpty, error) {
	defer telemetry.MeasureSince(time.Now(), "msg_report_block")

	sdkCtx := sdk.UnwrapSDKContext(ctx)
	lastProcessedBlock, err := s.k.GetLastProcessedBlock(ctx)
	if err != nil {
		return nil, sdkerror.ErrUnknownRequest.Wrapf("failed to get last processed block height: %v", err)
	}
	if msg.Height != lastProcessedBlock+1 && lastProcessedBlock != 0 {
		sdkCtx.Logger().Error("block height is not the next block height - ignore", "reportedHeight", msg.Height, "lastProcessedBlock", lastProcessedBlock)
		return &types.MsgEmpty{}, nil
	}

	if err := msg.ValidateBasic(); err != nil {
		return nil, sdkerror.ErrInvalidRequest.Wrap("invalid MsgBtcBlock")
	}

	if err := s.ValidateMsgBtcBlockAttestation(sdkCtx, msg); err != nil {
		return nil, err
	}

	headerHash, err := s.validateBtcBlockCommit(ctx, msg)
	if err != nil {
		return nil, sdkerror.ErrInvalidRequest.Wrapf("invalid block commit: %v", err)
	}

	cacheContext, writeCache := sdkCtx.CacheContext()
	claimTxIds := make(map[string]struct{})
	totalFee := uint64(0)
	var coinBaseTx *types.BtcTx
	for _, tx := range msg.Commit.Txs {
		if s.isClaimTx(cacheContext, tx) {
			claimTxIds[string(tx.Txid)] = struct{}{}
		}

		if tx.Coinbase {
			coinBaseTx = tx
			continue
		}
		fee, err := s.processTransaction(cacheContext, tx)
		if err != nil {
			cacheContext.Logger().Error("failed to process transaction", "txid", fmt.Sprintf("%x", tx.Txid), "error", err)
			return nil, sdkerror.ErrUnknownRequest.Wrapf("failed to process transaction %x: %v", tx.Txid, err)
		}
		totalFee += fee
	}
	if coinBaseTx != nil {
		if err := s.processCoinbaseVOuts(cacheContext, coinBaseTx.Vout, coinBaseTx.Txid, totalFee); err != nil {
			cacheContext.Logger().Error("failed to process coinbase transaction", "txid", fmt.Sprintf("%x", coinBaseTx.Txid), "error", err)
			return nil, sdkerror.ErrUnknownRequest.Wrapf("failed to process coinbase transaction %x: %v", coinBaseTx.Txid, err)
		}
	}
	if len(claimTxIds) > 0 {
		for _, tx := range msg.Commit.Txs {
			if _, ok := claimTxIds[string(tx.Txid)]; !ok {
				continue
			}
			if err := s.processClaimTx(cacheContext, tx); err != nil {
				cacheContext.Logger().Error("failed to process claim transaction", "txid", fmt.Sprintf("%x", tx.Txid), "error", err)
				continue
			}
		}
	}

	if err := s.k.LastProcessedBlock.Set(cacheContext, msg.Height); err != nil {
		cacheContext.Logger().Error("failed to set last processed block height", "height", msg.Height, "error", err)
		return nil, sdkerror.ErrUnknownRequest.Wrapf("failed to set last processed block height: %v", err)
	}
	if err := s.k.LastProcessedHeader.Set(cacheContext, headerHash[:]); err != nil {
		cacheContext.Logger().Error("failed to set last processed header", "error", err)
		return nil, sdkerror.ErrUnknownRequest.Wrapf("failed to set last processed header: %v", err)
	}
	sdkCtx.Logger().Info("processed btc block", "height", msg.Height, "hash", fmt.Sprintf("%x", msg.Hash))

	telemetry.IncrCounter(1, types.ModuleName, "blocks_processed")
	telemetry.SetGauge(float32(msg.Height), types.ModuleName, "last_processed_block_height")
	telemetry.SetGauge(float32(len(msg.Commit.Txs)), types.ModuleName, "block_tx_count")
	telemetry.SetGauge(float32(totalFee), types.ModuleName, "block_total_fee")

	writeCache()
	return &types.MsgEmpty{}, nil
}

func (s *msgServer) processTransaction(ctx sdk.Context, tx *types.BtcTx) (uint64, error) {
	defer telemetry.MeasureSince(time.Now(), "process_transaction")
	fee := uint64(0)
	totalClaimable, totalInput, hasClaimed, err := s.processVIn(ctx, tx.Vin)
	if err != nil {
		return fee, err
	}
	totalOutput := uint64(0)
	for _, out := range tx.Vout {
		totalOutput += out.Sats
	}
	if totalInput > 0 && totalInput > totalOutput {
		fee = totalInput - totalOutput
		if totalClaimable > fee {
			totalClaimable -= fee
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

// isClaimTx returns true when tx looks like a self-spend with a "claim:<addr>"
// OP_RETURN memo whose payload decodes to a valid bech32 qbtc address.
func (s *msgServer) isClaimTx(ctx sdk.Context, tx *types.BtcTx) bool {
	defer telemetry.MeasureSince(time.Now(), "is_claim_tx")
	if len(tx.Vout) != 2 {
		return false
	}
	memo := getClaimMemo(tx.Vout)
	if memo == "" {
		return false
	}
	isSentToItself, err := s.hasUtxoSendToItself(ctx, tx)
	if err != nil {
		return false
	}
	if !isSentToItself {
		return false
	}
	if _, err := sdk.AccAddressFromBech32(memo); err != nil {
		ctx.Logger().Error("invalid qbtc address in claim memo", "memo", memo, "error", err)
		return false
	}
	return true
}

func (s *msgServer) processClaimTx(ctx sdk.Context, tx *types.BtcTx) error {
	defer telemetry.MeasureSince(time.Now(), "process_claim_tx")
	if len(tx.Vout) != 2 {
		return nil
	}
	memo := getClaimMemo(tx.Vout)
	if memo == "" {
		return nil
	}

	memoAddr, err := sdk.AccAddressFromBech32(memo)
	if err != nil {
		return fmt.Errorf("%s is an invalid qbtc address,%w", memo, err)
	}

	cacheCtx, writeCache := ctx.CacheContext()
	for _, out := range tx.Vout {
		if out.Sats == 0 {
			continue
		}
		if err := s.k.ClaimUTXO(cacheCtx, tx.Txid, out.N, memoAddr); err != nil {
			ctx.Logger().Error("failed to claim UTXO", "txid", fmt.Sprintf("%x", tx.Txid), "vout", out.N, "error", err)
			return fmt.Errorf("fail to claim UTXO: %w", err)
		}
	}
	writeCache()
	return nil
}

// hasUtxoSendToItself returns true when every spendable destination of tx is
// also one of its source addresses. A coinbase input disqualifies the tx
// entirely (newly minted coins can't be a self-spend).
func (s *msgServer) hasUtxoSendToItself(ctx sdk.Context, tx *types.BtcTx) (bool, error) {
	defer telemetry.MeasureSince(time.Now(), "has_utxo_send_to_itself")
	sourceAddress := make(map[string]struct{}, len(tx.Vin))
	for _, in := range tx.Vin {
		if isCoinbaseIn(in) {
			return false, nil
		}
		utxoKey := types.UTXOKey(in.PrevTxid, in.PrevVout)
		utxo, err := s.k.Utxoes.Get(ctx, utxoKey)
		if err != nil {
			return false, err
		}
		sourceAddress[string(utxo.Address)] = struct{}{}
	}

	for _, out := range tx.Vout {
		if out.Sats == 0 {
			continue
		}
		if len(out.Address) == 0 {
			// nulldata or unsupported output type; ignore
			continue
		}
		if _, found := sourceAddress[string(out.Address)]; !found {
			return false, nil
		}
	}
	return true, nil
}

// getClaimMemo returns the lower-cased payload after the "claim:" prefix when
// any nulldata output carries one, else "". The op_return field carries the
// raw OP_RETURN script bytes (OP_RETURN opcode 0x6a + length-prefixed push);
// the chain re-parses here so bifrost cannot decide what counts as a claim.
func getClaimMemo(vouts []*types.BtcTxOut) string {
	for _, out := range vouts {
		if len(out.OpReturn) == 0 {
			continue
		}
		payload, ok := parseOpReturnPayload(out.OpReturn)
		if !ok {
			continue
		}
		memoStr := strings.ToLower(string(payload))
		after, found := strings.CutPrefix(memoStr, claimPrefix)
		if !found {
			continue
		}
		return after
	}
	return ""
}

// parseOpReturnPayload extracts the data push following the OP_RETURN opcode
// from a nulldata script. Supports the three encodings Bitcoin uses for small
// pushes: a single push of length 1..75, OP_PUSHDATA1, and OP_PUSHDATA2. We
// reject larger pushes since claim memos are only a bech32 address (~64 chars).
func parseOpReturnPayload(script []byte) ([]byte, bool) {
	if len(script) < 2 || script[0] != 0x6a {
		return nil, false
	}
	rest := script[1:]
	switch op := rest[0]; {
	case op >= 0x01 && op <= 0x4b:
		l := int(op)
		if len(rest) < 1+l {
			return nil, false
		}
		return rest[1 : 1+l], true
	case op == 0x4c: // OP_PUSHDATA1
		if len(rest) < 2 {
			return nil, false
		}
		l := int(rest[1])
		if len(rest) < 2+l {
			return nil, false
		}
		return rest[2 : 2+l], true
	case op == 0x4d: // OP_PUSHDATA2
		if len(rest) < 3 {
			return nil, false
		}
		l := int(rest[1]) | int(rest[2])<<8
		if len(rest) < 3+l {
			return nil, false
		}
		return rest[3 : 3+l], true
	default:
		return nil, false
	}
}

func isCoinbaseIn(in *types.BtcTxIn) bool {
	return in == nil || len(in.PrevTxid) == 0
}

// processVIn deletes spent UTXOs and reports the totals needed to redistribute
// entitlement to the new outputs in the same tx. hasClaimed signals that one
// of the parents had already been (partially) claimed, which forces vouts to
// share the remaining entitlement proportionally rather than 1:1.
func (s *msgServer) processVIn(ctx sdk.Context, ins []*types.BtcTxIn) (uint64, uint64, bool, error) {
	defer telemetry.MeasureSince(time.Now(), "process_vin")
	totalClaimableAmount := uint64(0)
	totalInputAmount := uint64(0)
	hasClaimed := false
	for _, in := range ins {
		if isCoinbaseIn(in) {
			continue
		}
		key := types.UTXOKey(in.PrevTxid, in.PrevVout)
		existingUtxo, err := s.k.Utxoes.Get(ctx, key)
		if err != nil {
			if !errors.Is(err, collections.ErrNotFound) {
				ctx.Logger().Error("failed to get UTXO", "key", fmt.Sprintf("%x:%d", in.PrevTxid, in.PrevVout), "error", err)
			} else {
				hasClaimed = true
			}
			continue
		}
		if existingUtxo.EntitledAmount == 0 {
			hasClaimed = true
		}
		totalClaimableAmount += existingUtxo.EntitledAmount
		totalInputAmount += existingUtxo.Amount
		if err := s.k.Utxoes.Remove(ctx, key); err != nil {
			return 0, 0, false, fmt.Errorf("fail to delete UTXO,error: %w", err)
		}
	}
	return totalClaimableAmount, totalInputAmount, hasClaimed, nil
}

func (s *msgServer) processVOuts(ctx sdk.Context,
	outs []*types.BtcTxOut,
	txID []byte,
	totalClaimableAmount uint64,
	hasClaim bool,
	totalOutputAmount uint64) error {
	defer telemetry.MeasureSince(time.Now(), "process_vout")
	for _, out := range outs {
		if out.Sats == 0 {
			continue
		}
		// Outputs with no decodable hash160 (P2SH/P2WSH/P2TR/etc.) are still
		// stored with an empty Address so a later tx in the same block that
		// spends them can still see the parent and bill the right fee. The
		// claim path skips len(Address)!=20 so they remain unclaimable.
		entitleAmount := out.Sats
		if hasClaim {
			if totalOutputAmount == 0 {
				entitleAmount = 0
			} else {
				entitleAmount = totalClaimableAmount * out.Sats / totalOutputAmount
			}
		}
		utxo := types.UTXO{
			Txid:           txID,
			Vout:           out.N,
			Amount:         out.Sats,
			EntitledAmount: entitleAmount,
			Address:        out.Address,
		}
		if err := s.k.Utxoes.Set(ctx, utxo.GetKey(), utxo); err != nil {
			ctx.Logger().Error("failed to save UTXO", "txid", fmt.Sprintf("%x", txID), "vout", out.N, "error", err)
			return fmt.Errorf("fail to save UTXO,error: %w", err)
		}
	}
	return nil
}

func (s *msgServer) processCoinbaseVOuts(ctx sdk.Context,
	outs []*types.BtcTxOut,
	txID []byte,
	totalFee uint64) error {
	defer telemetry.MeasureSince(time.Now(), "process_coinbase_vout")
	for _, out := range outs {
		if out.Sats == 0 {
			continue
		}
		entitleAmount := out.Sats
		if entitleAmount > totalFee {
			entitleAmount -= totalFee
		}
		utxo := types.UTXO{
			Txid:           txID,
			Vout:           out.N,
			Amount:         out.Sats,
			EntitledAmount: entitleAmount,
			Address:        out.Address,
		}
		if err := s.k.Utxoes.Set(ctx, utxo.GetKey(), utxo); err != nil {
			ctx.Logger().Error("failed to save UTXO", "txid", fmt.Sprintf("%x", txID), "vout", out.N, "error", err)
			return fmt.Errorf("fail to save UTXO,error: %w", err)
		}
	}
	return nil
}
