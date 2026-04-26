package keeper

import (
	"context"
	"errors"

	"cosmossdk.io/collections"
	"cosmossdk.io/core/address"
	corestore "cosmossdk.io/core/store"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/btcq-org/qbtc/x/lp/types"
)

// Keeper owns the single BTC<->qbtc CLP pool, node-only LP records, and bond
// accounting. It calls into x/secured for sbtc mint/burn and BTC outbound
// queueing; it does not custody real BTC itself.
type Keeper struct {
	storeService corestore.KVStoreService
	cdc          codec.Codec
	addressCodec address.Codec

	authority string

	authKeeper    types.AuthKeeper
	bankKeeper    types.BankKeeper
	stakingKeeper types.StakingKeeper
	securedKeeper types.SecuredKeeper

	Schema collections.Schema

	Pool             collections.Item[types.Pool]
	LPs              collections.Map[string, types.LiquidityProvider]
	Bonds            collections.Map[string, types.Bond]
	PendingAdds      collections.Map[uint64, types.PendingAdd]
	PendingAddSeq    collections.Sequence
	PendingAddByNode collections.Map[string, uint64]
	ConstOverrides   collections.Map[string, int64]
}

func NewKeeper(
	storeService corestore.KVStoreService,
	cdc codec.Codec,
	addressCodec address.Codec,
	authKeeper types.AuthKeeper,
	bankKeeper types.BankKeeper,
	stakingKeeper types.StakingKeeper,
	securedKeeper types.SecuredKeeper,
	authority string,
) *Keeper {
	sb := collections.NewSchemaBuilder(storeService)
	k := &Keeper{
		storeService:  storeService,
		cdc:           cdc,
		addressCodec:  addressCodec,
		authority:     authority,
		authKeeper:    authKeeper,
		bankKeeper:    bankKeeper,
		stakingKeeper: stakingKeeper,
		securedKeeper: securedKeeper,

		Pool: collections.NewItem(sb, types.PoolKey, "pool",
			codec.CollValue[types.Pool](cdc)),
		LPs: collections.NewMap(sb, types.LPPrefix, "liquidity_providers",
			collections.StringKey, codec.CollValue[types.LiquidityProvider](cdc)),
		Bonds: collections.NewMap(sb, types.BondPrefix, "bonds",
			collections.StringKey, codec.CollValue[types.Bond](cdc)),
		PendingAdds: collections.NewMap(sb, types.PendingPrefix, "pending_adds",
			collections.Uint64Key, codec.CollValue[types.PendingAdd](cdc)),
		PendingAddSeq: collections.NewSequence(sb, types.PendingSeqKey, "pending_add_seq"),
		PendingAddByNode: collections.NewMap(sb,
			collections.NewPrefix("pending_add_by_node"),
			"pending_add_by_node",
			collections.StringKey, collections.Uint64Value),
		ConstOverrides: collections.NewMap(sb,
			collections.NewPrefix("const_overrides"),
			"const_overrides",
			collections.StringKey, collections.Int64Value),
	}
	schema, err := sb.Build()
	if err != nil {
		panic(err)
	}
	k.Schema = schema
	return k
}

func (k *Keeper) GetAuthority() string { return k.authority }

func (k *Keeper) ModuleAddress() sdk.AccAddress {
	return k.authKeeper.GetModuleAddress(types.ModuleName)
}

// GetParam reads a mimir-style int64 override, falling back to the module
// default. Unknown keys return 0; callers should validate with IsKnownParam.
func (k *Keeper) GetParam(ctx context.Context, key string) int64 {
	v, err := k.ConstOverrides.Get(ctx, key)
	if err == nil {
		return v
	}
	if !errors.Is(err, collections.ErrNotFound) {
		sdk.UnwrapSDKContext(ctx).Logger().Error(
			"failed to read const override", "key", key, "error", err)
	}
	return types.DefaultParams()[key]
}

func (k *Keeper) SetParam(ctx context.Context, key string, value int64) error {
	return k.ConstOverrides.Set(ctx, key, value)
}
