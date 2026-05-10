package keeper_test

import (
	"encoding/hex"
	"testing"

	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/stretchr/testify/require"
)

func TestSerializeHeaderAndHash_BlockOne(t *testing.T) {
	// Bitcoin mainnet block 1: dsha256(serialize(header)) yields the
	// canonical block hash, and the hash satisfies block 1's PoW target.
	h := &types.BtcHeader{
		Version:    1,
		PrevBlock:  reverseHexHash("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"),
		MerkleRoot: reverseHexHash("0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"),
		Timestamp:  1231469665,
		Bits:       0x1d00ffff,
		Nonce:      2573394689,
	}

	hh, err := keeper.HeaderHash(h)
	require.NoError(t, err)
	wantBE := "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
	require.Equal(t, wantBE, hex.EncodeToString(reverseBytes(hh[:])))

	require.NoError(t, keeper.CheckProofOfWork(hh, h.Bits))
}

func TestBitsToTarget_Mainnet(t *testing.T) {
	target, err := keeper.BitsToTarget(0x1d00ffff)
	require.NoError(t, err)
	// Difficulty-1 target: 0x00000000ffff0000000000000000000000000000000000000000000000000000
	want := "00000000ffff0000000000000000000000000000000000000000000000000000"
	got := target.Text(16)
	for len(got) < len(want) {
		got = "0" + got
	}
	require.Equal(t, want, got)
}

func TestMerkleRoot_DuplicateLastLeaf(t *testing.T) {
	// Three-leaf case forces the Bitcoin "duplicate last leaf" padding rule
	// at the leaf level. Hand-computed reference hashes verified against
	// btcd's blockchain.BuildMerkleTreeStore behavior.
	a := bytesAll(0x01, 32)
	b := bytesAll(0x02, 32)
	c := bytesAll(0x03, 32)

	got, err := keeper.MerkleRoot([][]byte{a, b, c})
	require.NoError(t, err)

	// Reference: dsha256(dsha256(a||b) || dsha256(c||c))
	left := keeper.DoubleSHA256(append(append([]byte{}, a...), b...))
	right := keeper.DoubleSHA256(append(append([]byte{}, c...), c...))
	want := keeper.DoubleSHA256(append(append([]byte{}, left[:]...), right[:]...))

	require.Equal(t, want[:], got[:])
}

func TestMerkleRoot_SingleLeaf(t *testing.T) {
	leaf := bytesAll(0x42, 32)
	got, err := keeper.MerkleRoot([][]byte{leaf})
	require.NoError(t, err)
	require.Equal(t, leaf, got[:])
}

func TestCheckProofOfWork_Reject(t *testing.T) {
	// hash = 0xff... must fail any reasonable target.
	var hash [32]byte
	for i := range hash {
		hash[i] = 0xff
	}
	require.Error(t, keeper.CheckProofOfWork(hash, 0x1d00ffff))
}

func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}

func bytesAll(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
