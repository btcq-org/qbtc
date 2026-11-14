package keeper

import (
	"context"
	"errors"

	"cosmossdk.io/collections"
)

// NextUtxoChunk returns the index and hash of the next genesis UTXO chunk to
// load, or done when every chunk is in state (or the chain has no snapshot).
func (k Keeper) NextUtxoChunk(ctx context.Context) (index uint64, hash []byte, done bool, err error) {
	index, err = k.UtxoChunksLoaded.Get(ctx)
	if err != nil && !errors.Is(err, collections.ErrNotFound) {
		return 0, nil, false, err
	}
	hash, err = k.UtxoChunkHashes.Get(ctx, index)
	if errors.Is(err, collections.ErrNotFound) {
		return index, nil, true, nil
	}
	if err != nil {
		return 0, nil, false, err
	}
	return index, hash, false, nil
}

// MarkUtxoChunkLoaded records that chunk index is in state. Progress lives in
// state, so a block that is executed again, after a crash or by optimistic
// execution, loads the same chunk again from the committed progress.
func (k Keeper) MarkUtxoChunkLoaded(ctx context.Context, index uint64) error {
	return k.UtxoChunksLoaded.Set(ctx, index+1)
}

// UtxoSnapshotLoaded reports whether every genesis UTXO chunk is in state.
// Bitcoin blocks apply only after that: a block applied earlier could spend a
// UTXO that a later chunk then writes back.
func (k Keeper) UtxoSnapshotLoaded(ctx context.Context) (bool, error) {
	_, _, done, err := k.NextUtxoChunk(ctx)
	return done, err
}
