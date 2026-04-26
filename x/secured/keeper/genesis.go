package keeper

import (
	"context"

	"github.com/btcq-org/qbtc/x/secured/types"
)

func (k *Keeper) InitGenesis(ctx context.Context, gs *types.GenesisState) error {
	if gs.Vault != nil {
		if err := k.Vault.Set(ctx, *gs.Vault); err != nil {
			return err
		}
	}
	if err := k.TxOutSeq.Set(ctx, gs.TxOutSeq); err != nil {
		return err
	}
	for _, item := range gs.TxOutQueue {
		if err := k.TxOutQueue.Set(ctx, item.Id, item); err != nil {
			return err
		}
	}
	for _, p := range gs.Params {
		if err := k.ConstOverrides.Set(ctx, p.Key, p.Value); err != nil {
			return err
		}
	}
	return nil
}

func (k *Keeper) ExportGenesis(ctx context.Context) (*types.GenesisState, error) {
	gs := &types.GenesisState{}

	v, err := k.Vault.Get(ctx)
	if err == nil {
		gs.Vault = &v
	}

	seq, err := k.TxOutSeq.Peek(ctx)
	if err == nil {
		gs.TxOutSeq = seq
	}

	if err := k.TxOutQueue.Walk(ctx, nil, func(_ uint64, item types.TxOutItem) (bool, error) {
		gs.TxOutQueue = append(gs.TxOutQueue, item)
		return false, nil
	}); err != nil {
		return nil, err
	}

	if err := k.ConstOverrides.Walk(ctx, nil, func(key string, value int64) (bool, error) {
		gs.Params = append(gs.Params, types.Param{Key: key, Value: value})
		return false, nil
	}); err != nil {
		return nil, err
	}
	return gs, nil
}
