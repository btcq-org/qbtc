package types

import "cosmossdk.io/collections"

const (
	ModuleName = "secured"
	StoreKey   = ModuleName

	// HoldingAccountName buffers freshly-minted sbtc between observation
	// finalization and routing into x/lp. Funds rest here for at most one block.
	HoldingAccountName = "secured_holding"

	DenomSecuredBTC = "sbtc"
)

var (
	VaultKey            = collections.NewPrefix("vault")
	TxOutQueueKey       = collections.NewPrefix("tx_out_queue")
	TxOutSeqKey         = collections.NewPrefix("tx_out_seq")
	ObservedInboundKey  = collections.NewPrefix("observed_inbound")
	ObservedOutboundKey = collections.NewPrefix("observed_outbound")
	ConstOverridesKey   = collections.NewPrefix("const_overrides")
)
