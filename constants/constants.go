//go:build !mocknet && !stagenet

package constants

var DefaultValues = map[ConstantName]int64{
	EmissionCurve:        5,
	BlocksPerYear:        10 * 60 * 24 * 365, // 10 blocks per minute
	ZKEntropyThreshold:   4,                  // Minimum 4 validators for distributed setup
	ZKEntropyBlockWindow: 100,                // 100 blocks to collect all entropy
}
