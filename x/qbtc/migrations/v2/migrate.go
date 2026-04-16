package v2

import (
	"context"

	"cosmossdk.io/collections"

	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// MigrateStore rebuilds the Utxoes ByAddress secondary index for entries that
// were written before the index existed (ConsensusVersion 1).
//
// The index is populated by collections.IndexedMap on Set, so pre-existing
// UTXOs need to be re-Set once so the new `idx_utxo_by_addr` prefix is filled.
// Writes during Walk are safe: the underlying cachekv iterator snapshots the
// dirty cache at creation, and the IAVL iterator runs against an immutable
// tree version, so per-key Set inside the callback does not perturb the walk.
func MigrateStore(
	ctx context.Context,
	utxoes *collections.IndexedMap[string, types.UTXO, types.UTXOIndexes],
) error {
	return utxoes.Walk(ctx, nil, func(key string, utxo types.UTXO) (stop bool, err error) {
		if err := utxoes.Set(ctx, key, utxo); err != nil {
			return true, err
		}
		return false, nil
	})
}
