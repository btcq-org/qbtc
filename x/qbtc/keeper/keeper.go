package keeper

import (
	"cosmossdk.io/collections"
	"cosmossdk.io/core/address"
	corestore "cosmossdk.io/core/store"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/cosmos/cosmos-sdk/codec"
)

type Keeper struct {
	storeService corestore.KVStoreService
	cdc          codec.Codec
	addressCodec address.Codec

	// Authority is the address of the governance module
	authority string

	// Keepers
	stakingKeeper types.StakingKeeper
	bankKeeper    types.BankKeeper

	// Collections
	Schema  collections.Schema
	Utxoes  collections.Map[string, types.UTXO]
	NodeIPs collections.Map[string, string]
}

func NewKeeper(
	storeService corestore.KVStoreService,
	cdc codec.Codec,
	addressCodec address.Codec,
	stakingKeeper types.StakingKeeper,
	bankKeeper types.BankKeeper,
	authority string,
) Keeper {
	sb := collections.NewSchemaBuilder(storeService)
	k := Keeper{
		storeService:  storeService,
		cdc:           cdc,
		addressCodec:  addressCodec,
		stakingKeeper: stakingKeeper,
		bankKeeper:    bankKeeper,
		authority:     authority,
		Utxoes:        collections.NewMap(sb, types.UTXOKeys, "utxoes", collections.StringKey, codec.CollValue[types.UTXO](cdc)),
		NodeIPs:       collections.NewMap(sb, types.NodeIPKeys, "node_ips", collections.StringKey, collections.StringValue),
	}
	schema, err := sb.Build()
	if err != nil {
		panic(err)
	}
	k.Schema = schema

	return k
}

func (k Keeper) GetAuthority() string {
	return k.authority
}
