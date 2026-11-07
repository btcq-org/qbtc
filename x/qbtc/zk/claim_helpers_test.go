//go:build testing

package zk

import (
	"encoding/base64"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/stretchr/testify/require"
)

// signClaimForTest signs the claim message like a wallet would (BIP-137
// compact signature, base64) and runs it through ParseBIP137Signature. It
// returns the prover input, the base64 signature and SHA256 of the compressed
// pubkey. zktest.SignClaim offers the same to other packages; this package
// cannot import it without a cycle.
func signClaimForTest(t *testing.T, priv *btcec.PrivateKey, chainID, bitcoinAddress, qbtcAddress string) (ProofParams, string, [32]byte) {
	t.Helper()
	digest := ClaimMessageDigest(chainID, bitcoinAddress, qbtcAddress)
	sigBase64 := base64.StdEncoding.EncodeToString(btcecdsa.SignCompact(priv, digest[:], true))

	pub, r, s, err := ParseBIP137Signature(sigBase64, digest)
	require.NoError(t, err)
	require.True(t, pub.IsEqual(priv.PubKey()), "recovered key must be the signing key")

	pubKeyHashSHA256, err := PubKeyHashSHA256(pub.SerializeCompressed())
	require.NoError(t, err)
	return ProofParamsFromSignature(pub, r, s, digest), sigBase64, pubKeyHashSHA256
}

// signCompactBase64 is signClaimForTest without the assertions, for benchmarks.
func signCompactBase64(priv *btcec.PrivateKey, digest [32]byte) string {
	return base64.StdEncoding.EncodeToString(btcecdsa.SignCompact(priv, digest[:], true))
}
