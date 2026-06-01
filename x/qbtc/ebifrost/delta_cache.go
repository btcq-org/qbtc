package ebifrost

import (
	context "context"

	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// cloneBtcBlockDelta returns a deep copy so the cache owns immutable snapshots:
// callers cannot mutate stored/returned deltas (and thus the attested/injected
// bytes) outside the lock. Round-tripping through proto is simplest and
// guaranteed-correct for the generated type.
func cloneBtcBlockDelta(d *types.BtcBlockDelta) *types.BtcBlockDelta {
	if d == nil {
		return nil
	}
	bz, err := d.Marshal()
	if err != nil {
		// Marshal of a generated message with no maps cannot fail in practice.
		panic(err)
	}
	c := &types.BtcBlockDelta{}
	if err := c.Unmarshal(bz); err != nil {
		panic(err)
	}
	return c
}

// SendBTCBlockDelta feeds an observed minimal Bitcoin block delta into the
// node's cache. ExtendVote attests the digests of cached deltas; PrepareProposal
// pulls the full delta bytes for the height that reached quorum.
func (eb *EnshrinedBifrost) SendBTCBlockDelta(ctx context.Context, delta *types.BtcBlockDelta) (*SendBTCBlockResponse, error) {
	if eb == nil || delta == nil {
		return &SendBTCBlockResponse{}, nil
	}
	eb.deltaMu.Lock()
	eb.btcDeltaCache[uint64(delta.Height)] = cloneBtcBlockDelta(delta)
	eb.deltaMu.Unlock()
	return &SendBTCBlockResponse{}, nil
}

// ObservedDeltas returns a snapshot of cached deltas with height strictly above
// minHeight, up to limit entries (lowest heights first). Used by ExtendVote.
func (eb *EnshrinedBifrost) ObservedDeltas(minHeight uint64, limit int) []*types.BtcBlockDelta {
	if eb == nil {
		return nil
	}
	eb.deltaMu.RLock()
	defer eb.deltaMu.RUnlock()

	var out []*types.BtcBlockDelta
	// Walk contiguously from minHeight+1 so the returned deltas form a gap-free
	// run, which is what the proposer can actually apply in order.
	for h := minHeight + 1; ; h++ {
		d, ok := eb.btcDeltaCache[h]
		if !ok {
			break
		}
		out = append(out, cloneBtcBlockDelta(d))
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// GetDelta returns the cached delta for a Bitcoin height, if present.
func (eb *EnshrinedBifrost) GetDelta(height uint64) (*types.BtcBlockDelta, bool) {
	if eb == nil {
		return nil, false
	}
	eb.deltaMu.RLock()
	defer eb.deltaMu.RUnlock()
	d, ok := eb.btcDeltaCache[height]
	return cloneBtcBlockDelta(d), ok
}

// PruneDeltasBelow drops cached deltas at or below height (already processed).
func (eb *EnshrinedBifrost) PruneDeltasBelow(height uint64) {
	if eb == nil {
		return
	}
	eb.deltaMu.Lock()
	defer eb.deltaMu.Unlock()
	for h := range eb.btcDeltaCache {
		if h <= height {
			delete(eb.btcDeltaCache, h)
		}
	}
}
