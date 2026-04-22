package zk

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestComputeClaimMessage_Deterministic(t *testing.T) {
	addressHash := [20]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	qbtcAddressHash := HashQBTCAddress("qbtc1testaddress")
	chainID := ComputeChainIDHash("qbtc-1")

	// Compute multiple times
	msg1 := ComputeClaimMessage(addressHash, qbtcAddressHash, chainID)
	msg2 := ComputeClaimMessage(addressHash, qbtcAddressHash, chainID)
	msg3 := ComputeClaimMessage(addressHash, qbtcAddressHash, chainID)

	require.Equal(t, msg1, msg2)
	require.Equal(t, msg2, msg3)
}

func TestComputeClaimMessage_IncludesAllInputs(t *testing.T) {
	baseAddressHash := [20]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	baseBtcqHash := HashQBTCAddress("qbtc1base")
	baseChainID := ComputeChainIDHash("qbtc-1")

	baseMessage := ComputeClaimMessage(baseAddressHash, baseBtcqHash, baseChainID)

	// Change address hash - should produce different message
	diffAddressHash := baseAddressHash
	diffAddressHash[0] ^= 0xFF
	diffByAddr := ComputeClaimMessage(diffAddressHash, baseBtcqHash, baseChainID)
	require.NotEqual(t, baseMessage, diffByAddr, "different address hash should produce different message")

	// Change QBTC address - should produce different message
	diffBtcqHash := HashQBTCAddress("qbtc1different")
	diffByBtcq := ComputeClaimMessage(baseAddressHash, diffBtcqHash, baseChainID)
	require.NotEqual(t, baseMessage, diffByBtcq, "different QBTC address should produce different message")

	// Change chain ID - should produce different message
	diffChainID := ComputeChainIDHash("other-chain-1")
	diffByChain := ComputeClaimMessage(baseAddressHash, baseBtcqHash, diffChainID)
	require.NotEqual(t, baseMessage, diffByChain, "different chain ID should produce different message")
}

func TestComputeClaimMessage_FormatCorrectness(t *testing.T) {
	addressHash := [20]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x12, 0x34, 0x56, 0x78}
	qbtcAddressHash := HashQBTCAddress("qbtc1test")
	chainIDHash := ComputeChainIDHash("qbtc-1")

	result := ComputeClaimMessage(addressHash, qbtcAddressHash, chainIDHash)

	// Verify by manually computing expected hash (including type prefix)
	var expected []byte
	expected = append(expected, []byte(ClaimTagECDSAHash160)...)
	expected = append(expected, addressHash[:]...)
	expected = append(expected, qbtcAddressHash[:]...)
	expected = append(expected, chainIDHash[:]...)
	expected = append(expected, []byte(ClaimMessageVersion)...)

	expectedHash := sha256.Sum256(expected)
	require.Equal(t, expectedHash, result)
}

func TestVerifyClaimMessage_Valid(t *testing.T) {
	addressHash := [20]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	qbtcAddressHash := HashQBTCAddress("qbtc1test")
	chainIDHash := ComputeChainIDHash("qbtc-1")

	messageHash := ComputeClaimMessage(addressHash, qbtcAddressHash, chainIDHash)

	// Should verify correctly
	valid := VerifyClaimMessage(messageHash, addressHash, qbtcAddressHash, chainIDHash)
	require.True(t, valid)
}

func TestVerifyClaimMessage_WrongInputs(t *testing.T) {
	addressHash := [20]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	qbtcAddressHash := HashQBTCAddress("qbtc1test")
	chainIDHash := ComputeChainIDHash("qbtc-1")

	messageHash := ComputeClaimMessage(addressHash, qbtcAddressHash, chainIDHash)

	// Wrong address hash
	wrongAddr := addressHash
	wrongAddr[0] ^= 0xFF
	require.False(t, VerifyClaimMessage(messageHash, wrongAddr, qbtcAddressHash, chainIDHash))

	// Wrong QBTC address
	wrongBtcq := HashQBTCAddress("qbtc1attacker")
	require.False(t, VerifyClaimMessage(messageHash, addressHash, wrongBtcq, chainIDHash))

	// Wrong chain ID
	wrongChain := ComputeChainIDHash("other-chain")
	require.False(t, VerifyClaimMessage(messageHash, addressHash, qbtcAddressHash, wrongChain))

	// Wrong message hash
	wrongMsg := messageHash
	wrongMsg[0] ^= 0xFF
	require.False(t, VerifyClaimMessage(wrongMsg, addressHash, qbtcAddressHash, chainIDHash))
}

func TestClaimMessageVersion(t *testing.T) {
	// Ensure the version string is set correctly
	require.Equal(t, "qbtc-claim-v1", ClaimMessageVersion)

	// The version string should be incorporated into the hash
	addressHash := [20]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	qbtcAddressHash := HashQBTCAddress("qbtc1test")
	chainIDHash := ComputeChainIDHash("qbtc-1")

	msg := ComputeClaimMessage(addressHash, qbtcAddressHash, chainIDHash)

	// Changing the version would change the message (simulate by computing without version)
	var dataWithoutVersion []byte
	dataWithoutVersion = append(dataWithoutVersion, addressHash[:]...)
	dataWithoutVersion = append(dataWithoutVersion, qbtcAddressHash[:]...)
	dataWithoutVersion = append(dataWithoutVersion, chainIDHash[:]...)

	hashWithoutVersion := sha256.Sum256(dataWithoutVersion)
	require.NotEqual(t, msg, hashWithoutVersion, "version string should affect the hash")
}
