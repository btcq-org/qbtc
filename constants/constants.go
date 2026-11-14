//go:build !mocknet && !stagenet

package constants

var DefaultValues = map[ConstantName]int64{
	// The Reserve pays out 1/EmissionCurve of its balance a year: 12.5%.
	EmissionCurve: 8,
	// 6.37 s blocks, the average measured on the current chain.
	BlocksPerYear: 4_950_000,
	// Claims stay off at genesis; governance enables them once the
	// relaunch fixes and the reclaim batches are in.
	ClaimWithProofDisabled:    1,
	MinUtxoConfirmationBlocks: 144, // ~1 day at ~10 min/block
	MemoClaimDisabled:         0,
	ReferrerRewardBps:         500, // 5% of the referred claim
	RefereeRewardBps:          0,
	MaxClaimsPerBlock:         200, // MsgClaimWithProof messages per block, each a PLONK verification
}
