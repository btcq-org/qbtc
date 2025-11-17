//go:build mocknet

package constants

var DefaultValues = map[ConstantName]int64{
	EmissionCurve: 5,
	BlocksPerYear: 10 * 60 * 24 * 365, // 10 blocks per minute
}
