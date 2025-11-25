package constants

// ConstantName represents the names of various constants used in the application.
//
//go:generate stringer -type=ConstantName
type ConstantName int

const (
	EmissionCurve ConstantName = iota
	BlocksPerYear
	// ZKEntropyThreshold is the minimum number of active validators required
	// to submit entropy for the distributed ZK trusted setup.
	// Once this threshold is reached, the entropy can be combined to generate
	// the proving and verifying keys in a trust-minimized way.
	ZKEntropyThreshold
	// ZKEntropyBlockWindow is the number of blocks during which validators
	// can submit entropy after the threshold is reached.
	ZKEntropyBlockWindow
)

func FromString(s string) (ConstantName, bool) {
	switch s {
	case "EmissionCurve":
		return EmissionCurve, true
	case "BlocksPerYear":
		return BlocksPerYear, true
	case "ZKEntropyThreshold":
		return ZKEntropyThreshold, true
	case "ZKEntropyBlockWindow":
		return ZKEntropyBlockWindow, true
	default:
		return 0, false
	}
}
