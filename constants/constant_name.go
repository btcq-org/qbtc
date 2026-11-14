package constants

// ConstantName represents the names of various constants used in the application.
//
//go:generate stringer -type=ConstantName
type ConstantName int

const (
	EmissionCurve ConstantName = iota
	BlocksPerYear
	ClaimWithProofDisabled
	MinUtxoConfirmationBlocks
	MemoClaimDisabled
	// ReferrerRewardBps is the referrer's reward in basis points of the amount
	// a referred claim mints.
	ReferrerRewardBps
	// RefereeRewardBps is the reward in basis points of the claimed amount that
	// goes to the destination of a referred claim.
	RefereeRewardBps
)

// MaxRewardBps is the upper bound of the referral reward rates: 100%.
const MaxRewardBps = 10_000

func FromString(s string) (ConstantName, bool) {
	switch s {
	case "EmissionCurve":
		return EmissionCurve, true
	case "BlocksPerYear":
		return BlocksPerYear, true
	case "ClaimWithProofDisabled":
		return ClaimWithProofDisabled, true
	case "MinUtxoConfirmationBlocks":
		return MinUtxoConfirmationBlocks, true
	case "MemoClaimDisabled":
		return MemoClaimDisabled, true
	case "ReferrerRewardBps":
		return ReferrerRewardBps, true
	case "RefereeRewardBps":
		return RefereeRewardBps, true
	default:
		return 0, false
	}
}
