package common

// ChainNetwork is to indicate which chain environment BTCQ is working with
type ChainNetwork uint8

const (
	// TestNet network for test
	TestNet ChainNetwork = iota
	// MainNet network for mainnet
	MainNet
	// MockNet network for mocknet
	MockNet
	// Stagenet network for stagenet
	StageNet
)

// SoftEquals check is mainnet == mainnet, or mocknet == mocknet
func (net ChainNetwork) SoftEquals(net2 ChainNetwork) bool {
	return net == net2
}
