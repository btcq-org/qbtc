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
	AirdropEntryKeys = collections.NewPrefix("airdrop_entry")
	// ClaimedAirdropKeys is the prefix for tracking claimed airdrops
	ClaimedAirdropKeys = collections.NewPrefix("claimed_airdrop")

	// ZKEntropyStateKey is the key for the ZK entropy collection state
	ZKEntropyStateKey = collections.NewPrefix("zk_entropy_state")
	// ZKEntropySubmissionsKey is the prefix for individual validator entropy submissions
	ZKEntropySubmissionsKey = collections.NewPrefix("zk_entropy_submissions")
	// ZKSetupKeysKey is the key for the finalized ZK setup keys
	ZKSetupKeysKey = collections.NewPrefix("zk_setup_keys")
)
