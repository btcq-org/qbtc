package keeper

import (
	"context"
	"errors"

	"cosmossdk.io/collections"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/btcq-org/qbtc/x/secured/types"
)

// ObservedTxOut closes a queued TxOutItem after the bifrost signer set has
// broadcast the BTC tx and the chain has reached the configured confirmation
// depth. Idempotent on (broadcast txid).
func (s *msgServer) ObservedTxOut(
	ctx context.Context,
	msg *types.MsgObservedTxOut,
) (*types.MsgObservedTxOutResponse, error) {
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}

	digest := CanonicalOutboundDigest(msg.TxOutId, msg.BroadcastTxid, msg.BtcBlockHeight)
	if err := s.k.VerifyAttestationPower(ctx, digest, msg.Attestations); err != nil {
		return nil, err
	}

	has, err := s.k.ObservedOutbound.Has(ctx, msg.BroadcastTxid)
	if err != nil {
		return nil, err
	}
	if has {
		return &types.MsgObservedTxOutResponse{}, nil
	}

	item, err := s.k.TxOutQueue.Get(ctx, msg.TxOutId)
	if err != nil {
		if errors.Is(err, collections.ErrNotFound) {
			return nil, types.ErrTxOutNotFound.Wrapf("id=%d", msg.TxOutId)
		}
		return nil, err
	}

	item.Status = types.OutboundStatus_OUTBOUND_STATUS_CONFIRMED
	item.BroadcastTxId = msg.BroadcastTxid
	if err := s.k.TxOutQueue.Set(ctx, msg.TxOutId, item); err != nil {
		return nil, err
	}
	if err := s.k.ObservedOutbound.Set(ctx, msg.BroadcastTxid, []byte{1}); err != nil {
		return nil, err
	}

	sdk.UnwrapSDKContext(ctx).EventManager().EmitEvent(
		sdk.NewEvent("secured_outbound_confirmed",
			sdk.NewAttribute("id", uintString(msg.TxOutId)),
			sdk.NewAttribute("broadcast_txid", msg.BroadcastTxid),
		),
	)
	return &types.MsgObservedTxOutResponse{}, nil
}
