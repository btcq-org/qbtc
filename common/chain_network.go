package common

// ChainNetwork is to indicate which chain environment THORNode are working with
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

// Soft Equals check is mainnet == mainet, or mocknet == mocknet
func (net ChainNetwork) SoftEquals(net2 ChainNetwork) bool {
	if net == MainNet && net2 == MainNet {
		return true
	}
	if net != MainNet && net2 != MainNet {
		return true
	}

	return false
}
