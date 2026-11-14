//go:build stagenet

package constants

var DefaultValues = map[ConstantName]int64{
	EmissionCurve:             5,
	BlocksPerYear:             10 * 60 * 24 * 365, // 10 blocks per minute
	ClaimWithProofDisabled:    0,
	MinUtxoConfirmationBlocks: 144, // ~1 day at ~10 min/block
	MemoClaimDisabled:         0,
	ReferrerRewardBps:         500, // 5% of the referred claim
	RefereeRewardBps:          0,
	MaxClaimsPerBlock:         200, // MsgClaimWithProof messages per block, each a PLONK verification
}
