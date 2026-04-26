package types_test

import (
	"errors"
	"testing"

	"cosmossdk.io/math"

	"github.com/btcq-org/qbtc/x/lp/types"
)

func u(v uint64) math.Uint { return math.NewUint(v) }

func TestCalcSwapOutput(t *testing.T) {
	cases := []struct {
		name          string
		x, inBal, out math.Uint
		want          math.Uint
		wantErr       error
	}{
		{"1pct of pool", u(100), u(10_000), u(10_000), u(98), nil},
		{"100pct of pool", u(10_000), u(10_000), u(10_000), u(2_500), nil},
		{"tiny vs deep pool rounds down", u(1), u(1_000_000), u(2_000_000), u(1), nil},
		{"zero input", u(0), u(10_000), u(10_000), math.ZeroUint(), types.ErrZeroInput},
		{"zero input pool", u(100), u(0), u(10_000), math.ZeroUint(), types.ErrZeroPool},
		{"zero output pool", u(100), u(10_000), u(0), math.ZeroUint(), types.ErrZeroPool},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := types.CalcSwapOutput(tc.x, tc.inBal, tc.out)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if !got.Equal(tc.want) {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestCalcSlipBps(t *testing.T) {
	cases := []struct {
		name      string
		x, inBal  math.Uint
		wantBps   uint64
	}{
		{"1pct in, ~99 bps", u(100), u(10_000), 99},
		{"100pct in, 5000 bps", u(10_000), u(10_000), 5_000},
		{"tiny in deep pool rounds to zero", u(1), u(10_000), 0},
		{"zero in", u(0), u(10_000), 0},
		{"empty pool, zero in", u(0), u(0), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := types.CalcSlipBps(tc.x, tc.inBal)
			if got.Uint64() != tc.wantBps {
				t.Fatalf("got %d bps, want %d", got.Uint64(), tc.wantBps)
			}
		})
	}
}

func TestCalcSymmetricLPUnits(t *testing.T) {
	cases := []struct {
		name                      string
		b, q, B, Q, P             math.Uint
		want                      math.Uint
		wantErr                   error
	}{
		{
			name: "first deposit returns btcAdded",
			b:    u(1_000), q: u(2_000), B: u(0), Q: u(0), P: u(0),
			want: u(1_000),
		},
		{
			name: "equal-ratio add gets pro-rata units",
			b:    u(1_000), q: u(2_000), B: u(10_000), Q: u(20_000), P: u(10_000),
			want: u(1_000),
		},
		{
			name: "off-ratio add - more qbtc than pool ratio",
			b:    u(500), q: u(1_000), B: u(10_000), Q: u(20_000), P: u(15_000),
			want: u(750),
		},
		{
			name: "imbalanced single-sided BTC matches asym formula",
			b:    u(2_000), q: u(0), B: u(10_000), Q: u(20_000), P: u(15_000),
			want: u(1_363),
		},
		{
			name:    "both zero rejected",
			b:       u(0), q: u(0), B: u(10_000), Q: u(20_000), P: u(10_000),
			want:    math.ZeroUint(),
			wantErr: types.ErrZeroInput,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := types.CalcSymmetricLPUnits(tc.b, tc.q, tc.B, tc.Q, tc.P)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if !got.Equal(tc.want) {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestCalcWithdrawAmounts(t *testing.T) {
	cases := []struct {
		name                    string
		lpUnits                 math.Uint
		bps                     uint64
		poolUnits, B, Q         math.Uint
		wantBtc, wantQbtc, wantBurn math.Uint
		wantErr                 error
	}{
		{
			name:    "50pct withdraw of 10pct LP",
			lpUnits: u(1_000), bps: 5_000,
			poolUnits: u(10_000), B: u(100_000), Q: u(200_000),
			wantBtc: u(5_000), wantQbtc: u(10_000), wantBurn: u(500),
		},
		{
			name:    "100pct withdraw drains LP entirely",
			lpUnits: u(1_000), bps: 10_000,
			poolUnits: u(10_000), B: u(100_000), Q: u(200_000),
			wantBtc: u(10_000), wantQbtc: u(20_000), wantBurn: u(1_000),
		},
		{
			name:    "bps over 10000 rejected",
			lpUnits: u(1_000), bps: 10_001,
			poolUnits: u(10_000), B: u(100_000), Q: u(200_000),
			wantBtc: math.ZeroUint(), wantQbtc: math.ZeroUint(), wantBurn: math.ZeroUint(),
			wantErr: types.ErrBasisPointsRange,
		},
		{
			name:    "bps zero rejected",
			lpUnits: u(1_000), bps: 0,
			poolUnits: u(10_000), B: u(100_000), Q: u(200_000),
			wantBtc: math.ZeroUint(), wantQbtc: math.ZeroUint(), wantBurn: math.ZeroUint(),
			wantErr: types.ErrBasisPointsRange,
		},
		{
			name:    "zero LP units rejected",
			lpUnits: u(0), bps: 5_000,
			poolUnits: u(10_000), B: u(100_000), Q: u(200_000),
			wantBtc: math.ZeroUint(), wantQbtc: math.ZeroUint(), wantBurn: math.ZeroUint(),
			wantErr: types.ErrZeroInput,
		},
		{
			name:    "zero pool units rejected",
			lpUnits: u(1_000), bps: 5_000,
			poolUnits: u(0), B: u(100_000), Q: u(200_000),
			wantBtc: math.ZeroUint(), wantQbtc: math.ZeroUint(), wantBurn: math.ZeroUint(),
			wantErr: types.ErrZeroPoolUnits,
		},
		{
			name:    "withdraw rounds to zero units",
			lpUnits: u(1), bps: 1,
			poolUnits: u(10_000), B: u(100_000), Q: u(200_000),
			wantBtc: math.ZeroUint(), wantQbtc: math.ZeroUint(), wantBurn: math.ZeroUint(),
			wantErr: types.ErrZeroUnitsBurned,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotBtc, gotQbtc, gotBurn, err := types.CalcWithdrawAmounts(
				tc.lpUnits, tc.bps, tc.poolUnits, tc.B, tc.Q,
			)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if !gotBtc.Equal(tc.wantBtc) {
				t.Fatalf("btc = %s, want %s", gotBtc, tc.wantBtc)
			}
			if !gotQbtc.Equal(tc.wantQbtc) {
				t.Fatalf("qbtc = %s, want %s", gotQbtc, tc.wantQbtc)
			}
			if !gotBurn.Equal(tc.wantBurn) {
				t.Fatalf("burn = %s, want %s", gotBurn, tc.wantBurn)
			}
		})
	}
}

// TestRoundTripWithdraw is a property-style smoke test: depositing into a fresh
// pool (genesis-seeded with 1 sat / 1 unit) and withdrawing 100% should return
// the original deposit (modulo the 1-sat genesis seed retained by the pool) and
// burn exactly the units issued by the add.
func TestRoundTripWithdraw(t *testing.T) {
	// Genesis seed: B=1, Q=1, P=1.
	B, Q, P := u(1), u(1), u(1)

	b, q := u(1_000_000), u(1_000_000)
	units, err := types.CalcSymmetricLPUnits(b, q, B, Q, P)
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	newB := B.Add(b)
	newQ := Q.Add(q)
	newP := P.Add(units)

	btcOut, qbtcOut, burned, err := types.CalcWithdrawAmounts(units, 10_000, newP, newB, newQ)
	if err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if !burned.Equal(units) {
		t.Fatalf("burned %s, want %s", burned, units)
	}

	// Withdraw must not exceed deposited amounts and must leave at least the
	// 1-sat genesis seed in each side.
	if btcOut.GT(b) {
		t.Fatalf("btc out %s exceeds deposit %s", btcOut, b)
	}
	if qbtcOut.GT(q) {
		t.Fatalf("qbtc out %s exceeds deposit %s", qbtcOut, q)
	}
	if newB.Sub(btcOut).LT(u(1)) || newQ.Sub(qbtcOut).LT(u(1)) {
		t.Fatalf("pool drained below genesis seed: btc=%s qbtc=%s", newB.Sub(btcOut), newQ.Sub(qbtcOut))
	}
}
