package types

// Mimir-style parameter keys for the lp module. Stored as int64 in a
// ConstOverrides collection; defaults live in DefaultParams. Booleans encode
// as 0/1.
const (
	ParamMaxSlipBps              = "max_slip_bps"
	ParamPendingAddTimeoutBlocks = "pending_add_timeout_blocks"
	ParamPendingAddToleranceBps  = "pending_add_tolerance_bps"
	ParamMinAddSats              = "min_add_sats"
	ParamMinAddQbtc              = "min_add_qbtc"
	ParamRefundFeeReserveSats    = "refund_fee_reserve_sats"
	ParamOutboundEnabled         = "outbound_enabled"
	ParamBondLockedDuringChurn   = "bond_locked_during_churn"
)

// DefaultParams returns the default mimir values for the lp module.
func DefaultParams() map[string]int64 {
	return map[string]int64{
		ParamMaxSlipBps:              1_000,    // 10% slip cap
		ParamPendingAddTimeoutBlocks: 3_600,    // ≈ 6h at 6s blocks
		ParamPendingAddToleranceBps:  100,      // 1% BTC amount tolerance
		ParamMinAddSats:              10_000,   // 0.0001 BTC dust floor
		ParamMinAddQbtc:              10_000,
		ParamRefundFeeReserveSats:    5_000,    // held back from refunds for BTC fee
		ParamOutboundEnabled:         0,        // off by default until bifrost outbound is wired
		ParamBondLockedDuringChurn:   1,
	}
}

// IsKnownParam returns true if the key has a default value (i.e. is recognized
// by the module). Used by MsgUpdateParam.ValidateBasic to reject typos.
func IsKnownParam(key string) bool {
	_, ok := DefaultParams()[key]
	return ok
}
