package keeper

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/btcq-org/qbtc/x/secured/types"
)

// ObservedTxIn validates quorum, deduplicates each observation, mints sbtc to
// the holding account, and routes by memo prefix.
//
// Routing by memo (matches the qbtc memo grammar):
//
//	+:<pendingId>            -> LPHooks.OnObservedAddLiquidity
//	=:qbtc:<dest>:<min_out>  -> LPHooks.OnObservedSwapToQbtc
//
// All other memos (or LP hooks unset) cause the inbound to remain in the
// holding account and the operator must intervene; we do NOT auto-refund here
// because returning BTC requires a vault outbound and sender info that this
// handler treats as already-attested.
func (s *msgServer) ObservedTxIn(
	ctx context.Context,
	msg *types.MsgObservedTxIn,
) (*types.MsgObservedTxInResponse, error) {
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}

	digest := CanonicalObservationsDigest(msg.Observations)
	if err := s.k.VerifyAttestationPower(ctx, digest, msg.Attestations); err != nil {
		return nil, err
	}

	for i := range msg.Observations {
		obs := msg.Observations[i]
		if err := s.processObservation(ctx, &obs); err != nil {
			return nil, err
		}
	}
	return &types.MsgObservedTxInResponse{}, nil
}

func (s *msgServer) processObservation(ctx context.Context, obs *types.ObservedTxIn) error {
	key := fmt.Sprintf("%s:%d", obs.Txid, obs.Vout)

	has, err := s.k.ObservedInbound.Has(ctx, key)
	if err != nil {
		return err
	}
	if has {
		// Idempotent: same (txid, vout) already finalized.
		return nil
	}

	// Mark observed BEFORE side effects so a re-entry of the same observation
	// inside the same tx (extremely unlikely but defensive) hits the dedupe
	// branch. Atomic via the ambient cache context.
	if err := s.k.ObservedInbound.Set(ctx, key, []byte{1}); err != nil {
		return err
	}

	// Mint sbtc to holding regardless of whether routing succeeds — if hooks
	// are not registered or the memo is unrecognized, funds park in the
	// holding account and the operator must move them. This matches the
	// design choice of NOT auto-refunding from this handler.
	if err := s.k.MintSecured(ctx, obs.AmountSats, key); err != nil {
		return err
	}

	if s.k.lpHooks == nil {
		sdk.UnwrapSDKContext(ctx).Logger().Error(
			"observed inbound but lp hooks not set; sbtc parked in holding",
			"txid", obs.Txid, "vout", obs.Vout, "amount", obs.AmountSats.String())
		return nil
	}

	memo := strings.TrimSpace(obs.Memo)
	switch {
	case strings.HasPrefix(memo, "+:"):
		pendingID, err := strconv.ParseUint(strings.TrimPrefix(memo, "+:"), 10, 64)
		if err != nil {
			sdk.UnwrapSDKContext(ctx).Logger().Error(
				"add-liquidity memo with invalid pending id",
				"memo", memo, "error", err)
			return nil
		}
		return s.k.lpHooks.OnObservedAddLiquidity(ctx, pendingID, obs.AmountSats, obs.Txid)

	case strings.HasPrefix(memo, "=:qbtc:"):
		// =:qbtc:<dest>:<min_out>
		parts := strings.Split(strings.TrimPrefix(memo, "=:qbtc:"), ":")
		if len(parts) < 1 || parts[0] == "" {
			sdk.UnwrapSDKContext(ctx).Logger().Error(
				"swap-to-qbtc memo missing destination", "memo", memo)
			return nil
		}
		dest := parts[0]
		minOut := math.ZeroUint()
		if len(parts) >= 2 && parts[1] != "" {
			n, err := math.ParseUint(parts[1])
			if err != nil {
				sdk.UnwrapSDKContext(ctx).Logger().Error(
					"swap-to-qbtc memo with invalid min_out",
					"memo", memo, "error", err)
				return nil
			}
			minOut = n
		}
		return s.k.lpHooks.OnObservedSwapToQbtc(ctx, obs.AmountSats, dest, minOut, obs.Txid, obs.BtcSender)

	default:
		sdk.UnwrapSDKContext(ctx).Logger().Info(
			"observed inbound with unrecognized memo; sbtc parked in holding",
			"memo", memo, "txid", obs.Txid)
		return nil
	}
}
