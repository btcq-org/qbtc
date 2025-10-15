package common

import (
	"errors"
	"fmt"
	"math/big"
	"sort"

	"cosmossdk.io/math"
)

func Max[T int | uint | int64 | uint64](a, b T) T {
	if a > b {
		return a
	}
	return b
}

func Min[T int | uint | int64 | uint64](a, b T) T {
	if a < b {
		return a
	}
	return b
}

func Abs[T int | int64](a T) T {
	if a < 0 {
		return -a
	}
	return a
}

func GetMedianUint(vals []math.Uint) math.Uint {
	if len(vals) == 0 {
		return math.ZeroUint()
	}

	sort.SliceStable(vals, func(i, j int) bool {
		return vals[i].LT(vals[j])
	})

	// calculate median
	var median math.Uint
	if len(vals)%2 > 0 {
		// odd number of figures in our slice. Take the middle figure. Since
		// slices start with an index of zero, just need to length divide by two.
		medianSpot := len(vals) / 2
		median = vals[medianSpot]
	} else {
		// even number of figures in our slice. Average the middle two figures.
		pt1 := vals[len(vals)/2-1]
		pt2 := vals[len(vals)/2]
		median = pt1.Add(pt2).QuoUint64(2)
	}
	return median
}

func GetMedianInt64(vals []int64) int64 {
	switch len(vals) {
	case 0:
		return 0
	case 1:
		return vals[0]
	}

	sort.SliceStable(vals, func(i, j int) bool {
		return vals[i] < vals[j]
	})

	// calculate median
	var median int64
	if len(vals)%2 > 0 {
		// odd number of figures in our slice. Take the middle figure. Since
		// slices start with an index of zero, just need to length divide by two.
		medianSpot := len(vals) / 2
		median = vals[medianSpot]
	} else {
		// even number of figures in our slice. Average the middle two figures.
		pt1 := vals[len(vals)/2-1]
		pt2 := vals[len(vals)/2]
		median = (pt1 + pt2) / 2
	}
	return median
}

// WeightedMean calculates the weighted mean of a set of values and their weights.
func WeightedMean(vals, weights []math.Uint) (math.Uint, error) {

	totalWeight := Sum(weights)

	// if total weight is zero, return an error
	if totalWeight.IsZero() {
		return math.ZeroUint(), errors.New("total weight is zero")
	}

	// assert that the number of values and weights are the same
	if len(vals) != len(weights) {
		panic("number of values and weights do not match")
	}

	// calculate the weight in basis points for each anchor
	weightedTotal := math.ZeroUint()
	for i, val := range vals {
		weightedTotal = weightedTotal.Add(val.Mul(weights[i]))
	}

	return weightedTotal.Quo(totalWeight), nil
}

func MedianAbsoluteDeviation(values []*big.Float) (*big.Float, *big.Float, error) {
	median, err := GetMedianBigFloat(values)
	if err != nil {
		return nil, nil, err
	}

	deviations := make([]*big.Float, len(values))
	for i, value := range values {
		difference := new(big.Float).Sub(value, median)
		deviations[i] = new(big.Float).Abs(difference)
	}

	mad, err := GetMedianBigFloat(deviations)
	if err != nil {
		return nil, nil, err
	}

	return mad, median, nil
}

func GetMedianBigFloat(values []*big.Float) (*big.Float, error) {
	switch len(values) {
	case 0:
		return nil, fmt.Errorf("no values provided")
	case 1:
		return values[0], nil
	}

	sort.SliceStable(values, func(i, j int) bool {
		return values[i].Cmp(values[j]) < 0
	})

	if len(values)%2 > 0 {
		return values[len(values)/2], nil
	} else {
		midpoint := len(values) / 2
		sum := new(big.Float).Add(values[midpoint-1], values[midpoint])
		return new(big.Float).Quo(sum, big.NewFloat(2)), nil
	}
}

// SafeUintFromInt64 create a new Uint from an int64. It is expected that the int64 is
// positive - if not, we return zero to prevent overflow errors.
func SafeUintFromInt64(i int64) math.Uint {
	if i < 0 {
		return math.ZeroUint()
	}
	return math.NewUint(uint64(i))
}

// MinUint returns the minimum of two Uints.
func MinUint(u1, u2 math.Uint) math.Uint {
	if u1.LT(u2) {
		return u1
	}
	return u2
}

// Sum returns the sum of all the Uints in the slice.
func Sum(u []math.Uint) math.Uint {
	sum := math.ZeroUint()
	for _, i := range u {
		sum = sum.Add(i)
	}
	return sum
}

// SafeSub subtract input2 from input1, given cosmos.Uint can't be negative , otherwise it will panic
// thus in this method,when input2 is larger than input 1, it will just return cosmos.ZeroUint
func SafeSub(input1, input2 math.Uint) math.Uint {
	if input2.GT(input1) {
		return math.ZeroUint()
	}
	return input1.Sub(input2)
}
