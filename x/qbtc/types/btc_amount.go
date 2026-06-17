package types

import (
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
)

// BTCToSatoshis converts a BTC amount decoded from bitcoind JSON to satoshis.
// The conversion must round to nearest, not truncate: float64 decoding of an
// 8-decimal BTC string can land just below the exact satoshi value, so
// uint64(value * 1e8) would be 1 satoshi low. All valid amounts (≤ 21M BTC)
// are below 2^53 satoshis, so the rounded result is always exact.
func BTCToSatoshis(value float64) (uint64, error) {
	amount, err := btcutil.NewAmount(value)
	if err != nil {
		return 0, fmt.Errorf("invalid bitcoin amount %v: %w", value, err)
	}
	if amount < 0 {
		return 0, fmt.Errorf("negative bitcoin amount %v", value)
	}
	return uint64(amount), nil
}
