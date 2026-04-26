package types

const (
	ParamObserveQuorumNum         = "observe_quorum_num"
	ParamObserveQuorumDen         = "observe_quorum_den"
	ParamOutboundConfirmations    = "outbound_confirmations"
	ParamMaxOutboundQueueDepth    = "max_outbound_queue_depth"
	ParamMaxOutboundDispatchPerBlock = "max_outbound_dispatch_per_block"
	ParamOutboundStuckBlocks      = "outbound_stuck_blocks"
	ParamMaxOutboundRetries       = "max_outbound_retries"
	ParamChurnBlocks              = "churn_blocks"
	ParamChurnInCount             = "churn_in_count"
	ParamChurnOutCount            = "churn_out_count"
	ParamOutboundEnabled          = "outbound_enabled"
)

func DefaultParams() map[string]int64 {
	return map[string]int64{
		ParamObserveQuorumNum:            2,
		ParamObserveQuorumDen:            3,
		ParamOutboundConfirmations:       3,
		ParamMaxOutboundQueueDepth:       1_000,
		ParamMaxOutboundDispatchPerBlock: 16,
		ParamOutboundStuckBlocks:         600,   // ≈ 1h at 6s blocks
		ParamMaxOutboundRetries:          3,
		ParamChurnBlocks:                 43_200, // ≈ 3 days
		ParamChurnInCount:                4,
		ParamChurnOutCount:               3,
		ParamOutboundEnabled:             0,      // off until bifrost outbound lands
	}
}

func IsKnownParam(key string) bool {
	_, ok := DefaultParams()[key]
	return ok
}
