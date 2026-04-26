package keeper

import (
	"context"
	"errors"

	"cosmossdk.io/collections"
	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/btcq-org/qbtc/x/lp/types"
)

// nextPendingID atomically allocates a 1-based pending-add id.
func (k *Keeper) nextPendingID(ctx context.Context) (uint64, error) {
	n, err := k.PendingAddSeq.Next(ctx)
	if err != nil {
		return 0, err
	}
	return n + 1, nil
}

// CreatePending opens a pending-add intent for a node. Refuses to create a
// second open intent for the same node — caller must let the existing one
// expire or match first.
func (k *Keeper) CreatePending(
	ctx context.Context,
	nodeID, btcAddress string,
	qbtcLocked, expectedBTC math.Uint,
	toleranceBps uint32,
) (types.PendingAdd, error) {
	if _, err := k.PendingAddByNode.Get(ctx, nodeID); err == nil {
		return types.PendingAdd{}, types.ErrPendingAddOpen.Wrapf("node %s", nodeID)
	} else if !errors.Is(err, collections.ErrNotFound) {
		return types.PendingAdd{}, err
	}

	id, err := k.nextPendingID(ctx)
	if err != nil {
		return types.PendingAdd{}, err
	}
	height := sdk.UnwrapSDKContext(ctx).BlockHeight()
	timeout := k.GetParam(ctx, types.ParamPendingAddTimeoutBlocks)
	pa := types.PendingAdd{
		Id:              id,
		NodeId:          nodeID,
		BtcAddress:      btcAddress,
		QbtcLocked:      qbtcLocked,
		ExpectedBtc:     expectedBTC,
		ToleranceBps:    toleranceBps,
		CreatedHeight:   height,
		ExpiresAtHeight: height + timeout,
		Status:          types.PendingStatus_PENDING_STATUS_OPEN,
	}
	if err := k.PendingAdds.Set(ctx, id, pa); err != nil {
		return types.PendingAdd{}, err
	}
	if err := k.PendingAddByNode.Set(ctx, nodeID, id); err != nil {
		return types.PendingAdd{}, err
	}
	return pa, nil
}

// closePending removes the per-node index entry and updates the status. The
// PendingAdd row remains for audit and is removed only by the expiry sweep
// once it's terminal AND aged.
func (k *Keeper) closePending(ctx context.Context, pa *types.PendingAdd, status types.PendingStatus) error {
	pa.Status = status
	if err := k.PendingAdds.Set(ctx, pa.Id, *pa); err != nil {
		return err
	}
	return k.PendingAddByNode.Remove(ctx, pa.NodeId)
}

// btcWithinTolerance returns true if observed sats are within toleranceBps of
// the declared expected amount. tolerance == 0 means exact match.
func btcWithinTolerance(observed, expected math.Uint, toleranceBps uint32) bool {
	if expected.IsZero() {
		// No declared amount -> accept any non-zero observation. Used by
		// flows that don't require strict matching.
		return !observed.IsZero()
	}
	if toleranceBps == 0 {
		return observed.Equal(expected)
	}
	// |observed - expected| * 10000 <= expected * toleranceBps
	var diff math.Uint
	if observed.GT(expected) {
		diff = observed.Sub(expected)
	} else {
		diff = expected.Sub(observed)
	}
	lhs := diff.MulUint64(types.BasisPointsDenom)
	rhs := expected.MulUint64(uint64(toleranceBps))
	return lhs.LTE(rhs)
}
