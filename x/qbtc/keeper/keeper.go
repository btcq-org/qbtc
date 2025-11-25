package keeper

import (
	"context"
	"errors"

	"cosmossdk.io/collections"
	"cosmossdk.io/core/address"
	corestore "cosmossdk.io/core/store"
	"github.com/btcq-org/qbtc/constants"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
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
	authKeeper    types.AuthKeeper

	// Collections
	Schema            collections.Schema
	Utxoes            collections.Map[string, types.UTXO]
	NodePeerAddresses collections.Map[string, string]
	ConstOverrides    collections.Map[string, int64]

	// Airdrop collections
	// AirdropEntries maps btc address hash (hex) to airdrop amount
	AirdropEntries collections.Map[string, uint64]
	// ClaimedAirdrops tracks which address hashes have claimed (hex -> claimed bool)
	ClaimedAirdrops collections.Map[string, bool]
}

func NewKeeper(
	storeService corestore.KVStoreService,
	cdc codec.Codec,
	addressCodec address.Codec,
	stakingKeeper types.StakingKeeper,
	bankKeeper types.BankKeeper,
	authKeeper types.AuthKeeper,
	authority string,
) Keeper {
	sb := collections.NewSchemaBuilder(storeService)
	k := Keeper{
		storeService:      storeService,
		cdc:               cdc,
		addressCodec:      addressCodec,
		stakingKeeper:     stakingKeeper,
		bankKeeper:        bankKeeper,
		authority:         authority,
		Utxoes:            collections.NewMap(sb, types.UTXOKeys, "utxoes", collections.StringKey, codec.CollValue[types.UTXO](cdc)),
		NodePeerAddresses: collections.NewMap(sb, types.NodePeerAddressKeys, "node_peer_addresses", collections.StringKey, collections.StringValue),
		ConstOverrides:    collections.NewMap(sb, types.ConstOverrideKeys, "const_overrides", collections.StringKey, collections.Int64Value),
		authKeeper:        authKeeper,
		AirdropEntries:    collections.NewMap(sb, types.AirdropEntryKeys, "airdrop_entries", collections.StringKey, collections.Uint64Value),
		ClaimedAirdrops:   collections.NewMap(sb, types.ClaimedAirdropKeys, "claimed_airdrops", collections.StringKey, collections.BoolValue),
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

func (k Keeper) GetBalanceOfModule(ctx context.Context, moduleName string, denom string) sdk.Coin {
	moduleAddr := k.authKeeper.GetModuleAddress(moduleName)
	return k.bankKeeper.GetBalance(ctx, moduleAddr, denom)
}
func (k Keeper) GetConfig(ctx sdk.Context, constName constants.ConstantName) int64 {
	keyName := constName.String()
	// if the key is in constOverrides , which means nodes use mimir to override the const value
	// only mimir with super majority vote will be written into constOverrides
	v, err := k.ConstOverrides.Get(ctx, keyName)
	if err != nil {
		if !errors.Is(err, collections.ErrNotFound) {
			ctx.Logger().Error("failed to get const override", "const", keyName, "error", err)
		}
		return constants.DefaultValues[constName]
	}
	return v
}
