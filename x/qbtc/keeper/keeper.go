package keeper

import (
	"context"
	"errors"
	"fmt"

	"cosmossdk.io/collections"
	"cosmossdk.io/core/address"
	corestore "cosmossdk.io/core/store"
	"github.com/btcq-org/qbtc/constants"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/btcq-org/qbtc/x/qbtc/zk"
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

	LastProcessedBlock collections.Item[uint64]

	// LastProcessedHeader is the 32-byte dsha256 hash of the most recently
	// accepted Bitcoin block header. The next reported block must point its
	// prev_block field at this value.
	LastProcessedHeader collections.Item[[]byte]

	// ZK Verifying Key (stored as bytes in genesis, loaded at init)
	// The VK is stored in genesis and registered with the zk package at InitGenesis
	ZkVerifyingKey collections.Item[[]byte]
}

func NewKeeper(
	storeService corestore.KVStoreService,
	cdc codec.Codec,
	addressCodec address.Codec,
	stakingKeeper types.StakingKeeper,
	bankKeeper types.BankKeeper,
	authKeeper types.AuthKeeper,
	authority string,
) *Keeper {
	sb := collections.NewSchemaBuilder(storeService)
	k := &Keeper{
		storeService:       storeService,
		cdc:                cdc,
		addressCodec:       addressCodec,
		stakingKeeper:      stakingKeeper,
		bankKeeper:         bankKeeper,
		authority:          authority,
		authKeeper:         authKeeper,
		Utxoes:              collections.NewMap(sb, types.UTXOKeys, "utxoes", collections.StringKey, codec.CollValue[types.UTXO](cdc)),
		NodePeerAddresses:   collections.NewMap(sb, types.NodePeerAddressKeys, "node_peer_addresses", collections.StringKey, collections.StringValue),
		ConstOverrides:      collections.NewMap(sb, types.ConstOverrideKeys, "const_overrides", collections.StringKey, collections.Int64Value),
		ZkVerifyingKey:      collections.NewItem(sb, types.ZkVerifyingKeyKey, "zk_verifying_key", collections.BytesValue),
		LastProcessedBlock:  collections.NewItem(sb, types.LastProcessedBlockKey, "last_processed_block", collections.Uint64Value),
		LastProcessedHeader: collections.NewItem(sb, types.LastProcessedHeaderKey, "last_processed_header", collections.BytesValue),
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

func (k Keeper) GetLastProcessedBlock(ctx context.Context) (uint64, error) {
	v, err := k.LastProcessedBlock.Get(ctx)
	// if the last processed block is not found, return 0
	// this means  no block has been processed yet
	if errors.Is(err, collections.ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return v, nil
}

// EnsureZKVerifierInitialized loads the ZK verifying key from chain state and
// initializes the process-local global verifier if it has not been initialized
// yet.
//
// The verifier is an in-memory singleton and its state does not survive a node
// restart, whereas the VK is persisted in chain state. This method rehydrates
// the in-memory verifier from state so that claims continue to work after a
// restart, not only immediately after InitGenesis.
func (k Keeper) EnsureZKVerifierInitialized(ctx context.Context) error {
	if zk.IsVerifierInitialized() {
		return nil
	}

	vkBytes, err := k.ZkVerifyingKey.Get(ctx)
	if err != nil {
		if errors.Is(err, collections.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("failed to load ZK verifying key from state: %w", err)
	}
	if len(vkBytes) == 0 {
		return nil
	}

	if err := zk.InitializeVerifier(vkBytes); err != nil {
		return fmt.Errorf("failed to initialize ZK verifier: %w", err)
	}
	return nil
}
