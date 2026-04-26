package keeper

import (
	"context"
	"crypto/sha256"
	"sort"
	"strconv"

	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerror "github.com/cosmos/cosmos-sdk/types/errors"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/btcq-org/qbtc/x/secured/types"
)

// VerifyAttestationPower checks that the attestations carry strictly more than
// the configured quorum fraction (default 2/3) of bonded stake-weighted power
// over the supplied payload. Mirrors x/qbtc/keeper/handler_msg_report_block.go
// ValidateMsgBtcBlockAttestation but takes the payload as an argument so the
// same routine works for both inbound observations and outbound confirmations.
func (k *Keeper) VerifyAttestationPower(
	ctx context.Context,
	payload []byte,
	attestations []types.Attestation,
) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	validators, err := k.stakingKeeper.GetBondedValidatorsByPower(ctx)
	if err != nil {
		return sdkerror.ErrUnknownRequest.Wrapf("failed to get bonded validators: %v", err)
	}

	byCons := make(map[string]stakingtypes.Validator, len(validators))
	for _, v := range validators {
		pk, err := v.ConsPubKey()
		if err != nil {
			sdkCtx.Logger().Error("validator has no cons pubkey",
				"address", v.GetOperator(), "error", err)
			continue
		}
		byCons[sdk.ConsAddress(pk.Address()).String()] = v
	}

	validPower := math.ZeroInt()
	processed := make(map[string]bool, len(attestations))
	for _, a := range attestations {
		if processed[a.Address] {
			continue
		}
		processed[a.Address] = true

		v, ok := byCons[a.Address]
		if !ok {
			sdkCtx.Logger().Debug("attestation from non-bonded validator",
				"address", a.Address)
			continue
		}
		pk, err := v.ConsPubKey()
		if err != nil {
			continue
		}
		if !pk.VerifySignature(payload, a.Signature) {
			sdkCtx.Logger().Debug("attestation signature did not verify",
				"address", a.Address)
			continue
		}
		validPower = validPower.Add(math.NewInt(
			v.ConsensusPower(k.stakingKeeper.PowerReduction(ctx))))
	}

	totalPower, err := k.stakingKeeper.GetLastTotalPower(ctx)
	if err != nil {
		return sdkerror.ErrUnknownRequest.Wrapf("failed to get total power: %v", err)
	}
	num := math.NewInt(k.GetParam(ctx, types.ParamObserveQuorumNum))
	den := math.NewInt(k.GetParam(ctx, types.ParamObserveQuorumDen))
	if !den.IsPositive() {
		return sdkerror.ErrUnknownRequest.Wrap("invalid quorum denominator")
	}
	requiredPower := totalPower.Mul(num).Quo(den)
	if validPower.LTE(requiredPower) {
		return types.ErrInsufficientQuorum.Wrapf(
			"valid power %s, required > %s", validPower, requiredPower)
	}
	return nil
}

// CanonicalObservationsDigest returns the canonical SHA-256 digest validators
// must sign for a MsgObservedTxIn. Observations are sorted by (txid, vout)
// ascending before hashing so submission order is irrelevant.
func CanonicalObservationsDigest(obs []types.ObservedTxIn) []byte {
	sorted := make([]types.ObservedTxIn, len(obs))
	copy(sorted, obs)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Txid != sorted[j].Txid {
			return sorted[i].Txid < sorted[j].Txid
		}
		return sorted[i].Vout < sorted[j].Vout
	})

	h := sha256.New()
	for _, o := range sorted {
		// Tab-separated fields; trailing newline as record separator. Each
		// field is fixed-format so collisions across different observation
		// sets are not possible.
		_, _ = h.Write([]byte(o.Txid))
		_, _ = h.Write([]byte("\t"))
		_, _ = h.Write([]byte(strconv.FormatUint(uint64(o.Vout), 10)))
		_, _ = h.Write([]byte("\t"))
		_, _ = h.Write([]byte(o.BtcSender))
		_, _ = h.Write([]byte("\t"))
		_, _ = h.Write([]byte(o.BtcRecipient))
		_, _ = h.Write([]byte("\t"))
		_, _ = h.Write([]byte(o.AmountSats.String()))
		_, _ = h.Write([]byte("\t"))
		_, _ = h.Write([]byte(o.Memo))
		_, _ = h.Write([]byte("\t"))
		_, _ = h.Write([]byte(strconv.FormatUint(o.BtcBlockHeight, 10)))
		_, _ = h.Write([]byte("\n"))
	}
	return h.Sum(nil)
}

// CanonicalOutboundDigest returns the canonical digest validators sign for a
// MsgObservedTxOut: tx_out_id || ":" || broadcast_txid || ":" || btc_block_height.
func CanonicalOutboundDigest(txOutID uint64, broadcastTxid string, btcBlockHeight uint64) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte(strconv.FormatUint(txOutID, 10)))
	_, _ = h.Write([]byte(":"))
	_, _ = h.Write([]byte(broadcastTxid))
	_, _ = h.Write([]byte(":"))
	_, _ = h.Write([]byte(strconv.FormatUint(btcBlockHeight, 10)))
	return h.Sum(nil)
}
