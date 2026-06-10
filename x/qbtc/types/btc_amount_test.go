package types_test

import (
	"math"
	"strconv"
	"testing"

	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/stretchr/testify/require"
)

func TestBTCToSatoshis(t *testing.T) {
	cases := []struct {
		name string
		btc  float64
		want uint64
	}{
		{"zero", 0, 0},
		{"one satoshi", 0.00000001, 1},
		// 0.00000003 parses to 2.9999...e-8; truncation yields 2 instead of 3
		{"truncation victim small", 0.00000003, 3},
		{"truncation victim mid", 0.00000006, 6},
		{"one btc", 1.0, 1e8},
		{"max supply", 21_000_000, 2_100_000_000_000_000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := types.BTCToSatoshis(tc.btc)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}

	for name, bad := range map[string]float64{
		"nan":      math.NaN(),
		"pos inf":  math.Inf(1),
		"neg inf":  math.Inf(-1),
		"negative": -0.5,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := types.BTCToSatoshis(bad)
			require.Error(t, err)
		})
	}
}

// TestBTCToSatoshisRoundTrip verifies the conversion is exact for every
// satoshi value in ranges where plain truncation is known to lose 1 satoshi,
// using the same 8-decimal formatting bitcoind applies before JSON decoding.
func TestBTCToSatoshisRoundTrip(t *testing.T) {
	for _, base := range []uint64{1, 100_000, 100_000_000, 2_100_000_000_000_000 - 100_000} {
		for sat := base; sat < base+100_000; sat++ {
			s := strconv.FormatFloat(float64(sat)/1e8, 'f', 8, 64)
			f, err := strconv.ParseFloat(s, 64)
			require.NoError(t, err)
			got, err := types.BTCToSatoshis(f)
			require.NoError(t, err)
			require.Equal(t, sat, got, "value %s", s)
		}
	}
}
