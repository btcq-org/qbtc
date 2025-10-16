package types

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"cosmossdk.io/math"
	"github.com/btcq-org/btcq/common"
)

// Valid is to check whether the pool status is valid or not
func (x PoolStatus) Valid() error {
	if _, ok := PoolStatus_value[x.String()]; !ok {
		return errors.New("invalid pool status")
	}
	return nil
}

// MarshalJSON marshal PoolStatus to JSON in string form
func (x PoolStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(x.String())
}

// UnmarshalJSON convert string form back to PoolStatus
func (x *PoolStatus) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*x = GetPoolStatus(s)
	return nil
}

// GetPoolStatus from string
func GetPoolStatus(ps string) PoolStatus {
	if val, ok := PoolStatus_value[ps]; ok {
		return PoolStatus(val)
	}
	return PoolStatus_Suspended
}

// Pools represent a list of pools
type Pools []Pool

// NewPool Returns a new Pool
func NewPool() Pool {
	return Pool{
		BalanceRune:         math.ZeroUint(),
		BalanceAsset:        math.ZeroUint(),
		LPUnits:             math.ZeroUint(),
		PendingInboundRune:  math.ZeroUint(),
		PendingInboundAsset: math.ZeroUint(),
		Status:              PoolStatus_Available,
	}
}

// Valid check whether the pool is valid or not, if asset is empty then it is not valid
func (m Pool) Valid() error {
	if m.IsEmpty() {
		return errors.New("pool asset cannot be empty")
	}
	return nil
}

func (m *Pool) GetPoolUnits() math.Uint {
	return m.LPUnits
}

// IsEmpty will return true when the asset is empty
func (m Pool) IsEmpty() bool {
	return m.Asset.IsEmpty()
}

// IsAvailable check whether the pool is in Available status
func (m Pool) IsAvailable() bool {
	return m.Status == PoolStatus_Available
}

// IsStaged check whether the pool is in Staged status
func (m Pool) IsStaged() bool {
	return m.Status == PoolStatus_Staged
}

// String implement fmt.Stringer
func (m Pool) String() string {
	sb := strings.Builder{}
	sb.WriteString(fmt.Sprintln("rune-balance: " + m.BalanceRune.String()))
	sb.WriteString(fmt.Sprintln("asset-balance: " + m.BalanceAsset.String()))
	sb.WriteString(fmt.Sprintln("asset: " + m.Asset.String()))
	sb.WriteString(fmt.Sprintln("lp-units: " + m.LPUnits.String()))
	sb.WriteString(fmt.Sprintln("pending-inbound-rune: " + m.PendingInboundRune.String()))
	sb.WriteString(fmt.Sprintln("pending-inbound-asset: " + m.PendingInboundAsset.String()))
	sb.WriteString(fmt.Sprintln("status: " + m.Status.String()))
	sb.WriteString(fmt.Sprintln("decimals:" + strconv.FormatInt(m.Decimals, 10)))
	return sb.String()
}

func (m Pools) Get(asset common.Asset) (Pool, bool) {
	for _, p := range m {
		if p.Asset.Equals(asset) {
			return p, true
		}
	}
	return NewPool(), false
}

func (m Pools) Set(pool Pool) Pools {
	for i, p := range m {
		if p.Asset.Equals(pool.Asset) {
			m[i] = pool
		}
	}
	m = append(m, pool)
	return m
}
