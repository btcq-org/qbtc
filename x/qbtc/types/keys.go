package types

import "cosmossdk.io/collections"

const (
	// ModuleName defines the module name
	ModuleName = "qbtc"

	// StoreKey defines the primary module store key
	StoreKey = ModuleName

	// GovModuleName duplicates the gov module's name to avoid a dependency with x/gov.
	// It should be synced with the gov module's name if it is ever changed.
	// See: https://github.com/cosmos/cosmos-sdk/blob/v0.52.0-beta.2/x/gov/types/keys.go#L9
	GovModuleName = "gov"

	ReserveModuleName = "reserve"
)

var (
	// UTXOKeys is the prefix for UTXO store
	UTXOKeys = collections.NewPrefix("utxo")

	// NodePeerAddressKeys is the prefix for validators to store their node peer address
	NodePeerAddressKeys = collections.NewPrefix("node_peer_address")
	// ConstOverrideKeys is the prefix for constant overrides
	ConstOverrideKeys = collections.NewPrefix("const_override")

	// AirdropEntryKeys is the prefix for airdrop entries (keyed by Hash160 hex)
	// Deprecated: Use UTXO set instead
	AirdropEntryKeys = collections.NewPrefix("airdrop_entry")

	// ZkVerifyingKeyKey stores the PLONK verifying key for ZK proof verification
	ZkVerifyingKeyKey = collections.NewPrefix("zk_verifying_key")
)
