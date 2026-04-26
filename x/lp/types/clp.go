package types

import (
	"errors"

	"cosmossdk.io/math"
)

const BasisPointsDenom = uint64(10_000)

var (
	ErrZeroInput        = errors.New("amount must be greater than zero")
	ErrZeroPool         = errors.New("pool side must be greater than zero")
	ErrSlipExceedsLimit = errors.New("swap slip exceeds configured maximum")
	ErrOutBelowMinimum  = errors.New("swap output below caller minimum")
	ErrBasisPointsRange = errors.New("basis points must be in [1, 10000]")
	ErrZeroUnitsBurned  = errors.New("withdraw rounds to zero units")
	ErrZeroPoolUnits    = errors.New("pool units must be greater than zero")
)

// CalcSwapOutput returns the slip-based CLP output amount.
//
//	out = x * X * Y / (x + X)^2
//
// X is the pre-swap balance of the input side, Y of the output side.
// The slip fee (x^2 * Y / (x+X)^2) is retained inside the pool by construction —
// the caller updates pool balances with the *output* amount, so the pool keeps
// the difference between the constant-product output and this CLP output.
func CalcSwapOutput(x, inputBalance, outputBalance math.Uint) (math.Uint, error) {
	if x.IsZero() {
		return math.ZeroUint(), ErrZeroInput
	}
	if inputBalance.IsZero() || outputBalance.IsZero() {
		return math.ZeroUint(), ErrZeroPool
	}
	sum := x.Add(inputBalance)
	den := sum.Mul(sum)
	num := x.Mul(inputBalance).Mul(outputBalance)
	return num.Quo(den), nil
}

// CalcSlipBps returns the swap slip in basis points: x * 10_000 / (x + X).
func CalcSlipBps(x, inputBalance math.Uint) math.Uint {
	if x.IsZero() {
		return math.ZeroUint()
	}
	sum := x.Add(inputBalance)
	if sum.IsZero() {
		return math.ZeroUint()
	}
	return x.MulUint64(BasisPointsDenom).Quo(sum)
}

// CalcSymmetricLPUnits returns the LP units to issue for a symmetric add of
// (b BTC, q qbtc) into a pool currently holding (B, Q) with P units issued.
//
// Thornode 2-asset symmetric formula (RUNE drops out):
//
//	units = P * (b*Q + q*B + 2*b*q) / (b*Q + q*B + 2*B*Q)
//
// First-deposit branch (poolUnits == 0): seed with btcAdded. The genesis flow
// pre-seeds the pool with 1 sat / 1 unit so live adds never hit this branch,
// but it keeps the function total.
func CalcSymmetricLPUnits(btcAdded, qbtcAdded, btcBalance, qbtcBalance, poolUnits math.Uint) (math.Uint, error) {
	if btcAdded.IsZero() && qbtcAdded.IsZero() {
		return math.ZeroUint(), ErrZeroInput
	}
	if poolUnits.IsZero() {
		return btcAdded, nil
	}
	bQ := btcAdded.Mul(qbtcBalance)
	qB := qbtcAdded.Mul(btcBalance)
	twoBq := btcAdded.Mul(qbtcAdded).MulUint64(2)
	twoBQ := btcBalance.Mul(qbtcBalance).MulUint64(2)
	num := poolUnits.Mul(bQ.Add(qB).Add(twoBq))
	den := bQ.Add(qB).Add(twoBQ)
	if den.IsZero() {
		return math.ZeroUint(), ErrZeroPool
	}
	return num.Quo(den), nil
}

// CalcWithdrawAmounts computes the per-side outputs for a basis-points withdraw.
//
//	unitsBurned = lpUnits * bps / 10_000
//	out_side    = side_balance * unitsBurned / poolUnits
//
// All four returned values are zero if err != nil.
func CalcWithdrawAmounts(
	lpUnits math.Uint,
	basisPoints uint64,
	poolUnits, btcBalance, qbtcBalance math.Uint,
) (btcOut, qbtcOut, unitsBurned math.Uint, err error) {
	zero := math.ZeroUint()
	if basisPoints == 0 || basisPoints > BasisPointsDenom {
		return zero, zero, zero, ErrBasisPointsRange
	}
	if lpUnits.IsZero() {
		return zero, zero, zero, ErrZeroInput
	}
	if poolUnits.IsZero() {
		return zero, zero, zero, ErrZeroPoolUnits
	}
	unitsBurned = lpUnits.MulUint64(basisPoints).QuoUint64(BasisPointsDenom)
	if unitsBurned.IsZero() {
		return zero, zero, zero, ErrZeroUnitsBurned
	}
	btcOut = btcBalance.Mul(unitsBurned).Quo(poolUnits)
	qbtcOut = qbtcBalance.Mul(unitsBurned).Quo(poolUnits)
	return btcOut, qbtcOut, unitsBurned, nil
}
