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

var (
	PoolKey       = collections.NewPrefix("pool")
	ParamsKey     = collections.NewPrefix("params")
	LPPrefix      = collections.NewPrefix("lp")
	BondPrefix    = collections.NewPrefix("bond")
	PendingPrefix = collections.NewPrefix("pending_add")
	PendingSeqKey = collections.NewPrefix("pending_add_seq")
)
