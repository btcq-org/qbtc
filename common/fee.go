package common

import (
	"fmt"

	"cosmossdk.io/math"
)

// NewFee return a new instance of Fee
func NewFee(coins Coins, poolDeduct math.Uint) Fee {
	return Fee{
		Coins:      coins,
		PoolDeduct: poolDeduct,
	}
}

func (f Fee) String() string {
	return fmt.Sprintf("%d: %s", f.PoolDeduct.Uint64(), f.Coins.String())
}
