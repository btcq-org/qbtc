package ebifrost

import (
	"bytes"

	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// cachedDelta is an observed delta together with its precomputed digest, so the
// digest is hashed once (at store time) rather than on every ExtendVote read.
type cachedDelta struct {
	delta  *types.BtcBlockDelta
	digest []byte
}

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

// SetFloor publishes the chain's last-processed Bitcoin height (called by
// ExtendVote each block). The observer fetches above it; the cache is pruned at
// or below it.
func (eb *EnshrinedBifrost) SetFloor(height uint64) {
	if eb == nil {
		return
	}
	eb.floor.Store(height)
	eb.PruneDeltasBelow(height)
}

// storeDelta caches an observed delta (a deep copy) and its digest, keyed by
// Bitcoin height. Heights at or below the current floor are already processed
// and dropped, so a delta fetched just before the floor advanced is not
// reinserted behind it.
func (eb *EnshrinedBifrost) storeDelta(delta *types.BtcBlockDelta) {
	if eb == nil || delta == nil {
		return
	}
	if uint64(delta.Height) <= eb.floor.Load() {
		return
	}
	clone := cloneBtcBlockDelta(delta)
	entry := cachedDelta{delta: clone, digest: clone.Digest()}
	eb.deltaMu.Lock()
	eb.btcDeltaCache[uint64(clone.Height)] = entry
	eb.deltaMu.Unlock()
}

// ObservedAttests returns attestation digests for the contiguous run of cached
// deltas with height strictly above minHeight, up to limit entries. Used by
// ExtendVote; it copies only the small digest fields, never the full delta.
func (eb *EnshrinedBifrost) ObservedAttests(minHeight uint64, limit int) []*types.BtcBlockAttest {
	if eb == nil {
		return nil
	}
	eb.deltaMu.RLock()
	defer eb.deltaMu.RUnlock()

	var out []*types.BtcBlockAttest
	for h := minHeight + 1; ; h++ {
		c, ok := eb.btcDeltaCache[h]
		if !ok {
			break
		}
		out = append(out, &types.BtcBlockAttest{
			Height:    uint64(c.delta.Height),
			BlockHash: bytes.Clone(c.delta.BlockHash),
			DeltaHash: bytes.Clone(c.digest),
		})
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// GetDelta returns a deep copy of the cached delta for a Bitcoin height and its
// precomputed digest, if present. Used by PrepareProposal to inject the delta.
func (eb *EnshrinedBifrost) GetDelta(height uint64) (*types.BtcBlockDelta, []byte, bool) {
	if eb == nil {
		return nil, nil, false
	}
	eb.deltaMu.RLock()
	defer eb.deltaMu.RUnlock()
	c, ok := eb.btcDeltaCache[height]
	if !ok {
		return nil, nil, false
	}
	return cloneBtcBlockDelta(c.delta), bytes.Clone(c.digest), true
}

// hasDelta reports whether a delta for the given Bitcoin height is cached,
// without copying it. Used by the observer to skip heights it already has.
func (eb *EnshrinedBifrost) hasDelta(height uint64) bool {
	if eb == nil {
		return false
	}
	eb.deltaMu.RLock()
	defer eb.deltaMu.RUnlock()
	_, ok := eb.btcDeltaCache[height]
	return ok
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
