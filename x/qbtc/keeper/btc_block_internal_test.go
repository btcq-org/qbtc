package keeper

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// Real mainnet headers around the difficulty retarget at height 919296.
const (
	header917280 = "002051234acb45d3183b4f8ecb262c9fad3760b84bfd3da61909010000000000000000000caa52d9ba3bf3d7bdaf3f48761b7958e4c50f282d2bbce29528b84c93c340bc9987dd68b4dd01178f050a6b" // first block of the period
	header919295 = "0400f02f5ce8660343f270c5c0cb90d2c069e5a69b54b0f76e8a000000000000000000007dc9b6f78b18d51ce2bc08fbb99ef79b18fbf19d5450b0bc14fa1c924c40d6756881f068b4dd0117d2dc74d5" // last block of the period
	header919296 = "0000002090acfa4efd723aac00ddd6b6c9654790c067fccbb4d401000000000000000000cc9fb3eeb9e3c2d6c62fa1c51c7bc72caecd8c4ea1303f36e5de14cbf1a383893a8bf06821eb011731cb7a6d" // first block of the next period
)

func decodeHeader(t *testing.T, headerHex string) wire.BlockHeader {
	t.Helper()
	raw, err := hex.DecodeString(headerHex)
	require.NoError(t, err)
	var header wire.BlockHeader
	require.NoError(t, header.Deserialize(bytes.NewReader(raw)))
	return header
}

func TestRequiredBits_MainnetRetarget(t *testing.T) {
	params := &chaincfg.MainNetParams
	first := decodeHeader(t, header917280)
	last := decodeHeader(t, header919295)
	next := decodeHeader(t, header919296)
	require.Equal(t, "00000000000000000001d4b4cbfc67c0904765c9b6d6dd00ac3a72fd4efaac90", last.BlockHash().String())
	require.Equal(t, last.BlockHash(), next.PrevBlock)
	require.NotEqual(t, last.Bits, next.Bits, "the fixture must cross a retarget")

	tip := &btcTip{header: last, periodStart: first.Timestamp.Unix()}
	require.Equal(t, next.Bits, requiredBits(params, 919296, tip))

	// inside a period the bits do not change
	require.Equal(t, last.Bits, requiredBits(params, 919295, &btcTip{header: decodeHeader(t, header917280), periodStart: first.Timestamp.Unix()}))
	require.Equal(t, last.Bits, requiredBits(params, 919297, tip))
}

func TestRequiredBits_ClampsTheAdjustment(t *testing.T) {
	params := &chaincfg.MainNetParams
	last := decodeHeader(t, header919295)
	oldTarget := blockchain.CompactToBig(last.Bits)
	twoWeeks := int64(params.TargetTimespan / time.Second)

	// a period that took one second: the target shrinks by at most 4x
	fast := &btcTip{header: last, periodStart: last.Timestamp.Unix() - 1}
	quarter := blockchain.BigToCompact(oldTarget.Div(oldTarget, bigInt(4)))
	require.Equal(t, quarter, requiredBits(params, 919296, fast))

	// a period that took a year: the target grows by at most 4x
	slow := &btcTip{header: last, periodStart: last.Timestamp.Unix() - 26*twoWeeks}
	fourTimes := blockchain.BigToCompact(blockchain.CompactToBig(last.Bits).Mul(blockchain.CompactToBig(last.Bits), bigInt(4)))
	require.Equal(t, fourTimes, requiredBits(params, 919296, slow))
}

func TestRequiredBits_Regtest(t *testing.T) {
	params := &chaincfg.RegressionNetParams
	tip := &btcTip{header: wire.BlockHeader{Bits: 0x1d00ffff}}
	require.Equal(t, params.PowLimitBits, requiredBits(params, 2016, tip))
	require.Equal(t, params.PowLimitBits, requiredBits(params, 2017, tip))
}

func bigInt(n int64) *big.Int {
	return big.NewInt(n)
}
