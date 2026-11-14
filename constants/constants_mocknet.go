//go:build mocknet

package constants

var DefaultValues = map[ConstantName]int64{
	EmissionCurve:             5,
	BlocksPerYear:             10 * 60 * 24 * 365, // 10 blocks per minute
	ClaimWithProofDisabled:    0,
	MinUtxoConfirmationBlocks: 0, // disabled on mocknet for testing
	MemoClaimDisabled:         0,
	ReferrerRewardBps:         500, // 5% of the referred claim
	RefereeRewardBps:          100, // non-zero on mocknet so tests exercise the referee payout
}
