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

	// Keepers
	stakingKeeper types.StakingKeeper

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
) Keeper {
	sb := collections.NewSchemaBuilder(storeService)
	k := Keeper{
		storeService:  storeService,
		cdc:           cdc,
		addressCodec:  addressCodec,
		stakingKeeper: stakingKeeper,
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
