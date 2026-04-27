package types

import "cosmossdk.io/collections"

const (
	ModuleName = "lp"
	StoreKey   = ModuleName

	// GenesisSeedAccountName holds the permanent 1-unit dust that anchors
	// PoolUnits at genesis. Funds here are unreachable.
	GenesisSeedAccountName = "lp_genesis_seed"

	// BondedAccountName is the custody account for LP units that nodes have
	// bonded. Bank balance of lp/btc-qbtc on this account always equals
	// sum(Bond.UnitsBonded). When x/bond is split out as its own module, this
	// account moves there.
	BondedAccountName = "lp_bonded"

	ReserveAccountName = "lp_reserve"

	DenomSecuredBTC = "sbtc"
	// DenomLPUnit is the bank denom issued on add-liquidity and burned on
	// withdraw. Slashes in denoms are accepted by cosmos-sdk's bank denom
	// regex (token-factory uses the same convention).
	DenomLPUnit = "lp/btc-qbtc"
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
