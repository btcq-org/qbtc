package keeper

import (
	"context"
	"errors"

	"cosmossdk.io/collections"
	"cosmossdk.io/core/address"
	corestore "cosmossdk.io/core/store"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/btcq-org/qbtc/x/secured/types"
)

// Keeper owns the DKLS vault state, the sbtc denom mint/burn surface, and the
// outbound BTC TxOut queue consumed by bifrost. It is custody-aware but
// AMM-agnostic — x/lp registers an LPHooks instance to receive memo-routed
// observations.
type Keeper struct {
	storeService corestore.KVStoreService
	cdc          codec.Codec
	addressCodec address.Codec

	authority string

	authKeeper    types.AuthKeeper
	bankKeeper    types.BankKeeper
	stakingKeeper types.StakingKeeper

	// Set after NewKeeper via SetLPHooks; nil until x/lp registers itself,
	// which means inbound observations with LP-bound memos are refused (the
	// finalized sbtc stays in the holding account and the operator must set
	// the hooks before normal routing resumes).
	lpHooks types.LPHooks

	Schema collections.Schema

	Vault            collections.Item[types.Vault]
	TxOutQueue       collections.Map[uint64, types.TxOutItem]
	TxOutSeq         collections.Sequence
	ObservedInbound  collections.Map[string, []byte] // txid:vout -> sentinel (existence == finalized)
	ObservedOutbound collections.Map[string, []byte] // broadcast txid -> sentinel
	ConstOverrides   collections.Map[string, int64]
}

func NewKeeper(
	storeService corestore.KVStoreService,
	cdc codec.Codec,
	addressCodec address.Codec,
	authKeeper types.AuthKeeper,
	bankKeeper types.BankKeeper,
	stakingKeeper types.StakingKeeper,
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

		Vault: collections.NewItem(sb, types.VaultKey, "vault",
			codec.CollValue[types.Vault](cdc)),
		TxOutQueue: collections.NewMap(sb, types.TxOutQueueKey, "tx_out_queue",
			collections.Uint64Key, codec.CollValue[types.TxOutItem](cdc)),
		TxOutSeq: collections.NewSequence(sb, types.TxOutSeqKey, "tx_out_seq"),
		ObservedInbound: collections.NewMap(sb, types.ObservedInboundKey, "observed_inbound",
			collections.StringKey, collections.BytesValue),
		ObservedOutbound: collections.NewMap(sb, types.ObservedOutboundKey, "observed_outbound",
			collections.StringKey, collections.BytesValue),
		ConstOverrides: collections.NewMap(sb, types.ConstOverridesKey, "const_overrides",
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

func (k *Keeper) HoldingAddress() sdk.AccAddress {
	return k.authKeeper.GetModuleAddress(types.HoldingAccountName)
}

// SetLPHooks wires the x/lp side. Must be called once during app wiring,
// after both keepers are constructed.
func (k *Keeper) SetLPHooks(h types.LPHooks) {
	if k.lpHooks != nil {
		panic("secured: lp hooks already set")
	}
	k.lpHooks = h
}

// GetParam reads a mimir-style int64 override, falling back to the module's
// declared default. Unknown keys return 0 with no error to keep call sites
// terse; callers should validate keys via types.IsKnownParam.
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

// SetParam writes a mimir-style int64 override. Caller (the handler) is
// responsible for authority gating.
func (k *Keeper) SetParam(ctx context.Context, key string, value int64) error {
	return k.ConstOverrides.Set(ctx, key, value)
}

// OutboundEnabled is exposed on the SecuredKeeper expected-keeper for x/lp.
func (k *Keeper) OutboundEnabled(ctx context.Context) bool {
	return k.GetParam(ctx, types.ParamOutboundEnabled) != 0
}
