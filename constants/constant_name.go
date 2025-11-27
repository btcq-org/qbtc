package constants

// ConstantName represents the names of various constants used in the application.
//
//go:generate stringer -type=ConstantName
type ConstantName int

const (
	EmissionCurve ConstantName = iota
	BlocksPerYear
	ClaimWithProofDisabled
)

func FromString(s string) (ConstantName, bool) {
	switch s {
	case "EmissionCurve":
		return EmissionCurve, true
	case "BlocksPerYear":
		return BlocksPerYear, true
	case "ClaimWithProofDisabled":
		return ClaimWithProofDisabled, true
	default:
		return 0, false
	}
}
