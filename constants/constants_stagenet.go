//go:build stagenet

package constants

var DefaultValues = map[ConstantName]int64{
	EmissionCurve:        5,
	BlocksPerYear:        10 * 60 * 24 * 365, // 10 blocks per minute
	ZKEntropyThreshold:   3,                  // 3 validators for stagenet
	ZKEntropyBlockWindow: 50,                 // 50 blocks window for stagenet
}
