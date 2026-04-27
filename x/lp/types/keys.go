package types

import "cosmossdk.io/collections"

const (
	ModuleName = "lp"
	StoreKey   = ModuleName

	GenesisSeedAccountName = "lp_genesis_seed"
	ReserveAccountName     = "lp_reserve"

	DenomSecuredBTC = "sbtc"
	DenomLPUnit     = "lp-btc-qbtc"
)

// Collection prefixes. No prefix may be a byte-prefix of another (cosmossdk.io
// collections enforces this at schema build time). Names are pluralized or
// suffixed to ensure that.
var (
	PoolKey              = collections.NewPrefix("pool")
	ParamsKey            = collections.NewPrefix("params")
	LPsPrefix            = collections.NewPrefix("liquidity_providers")
	BondsPrefix          = collections.NewPrefix("bonds")
	PendingAddsPrefix    = collections.NewPrefix("pending_adds")
	PendingAddSeqKey     = collections.NewPrefix("pending_add_seq")
	PendingAddByNodeKey  = collections.NewPrefix("pending_add_by_node")
	ConstOverridesKey    = collections.NewPrefix("const_overrides")
)
