package zk

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/stretchr/testify/require"
)

// TestBIP137Vectors pins the digest construction and signature parsing against
// signatures produced by other implementations. Each vector is a message, the
// WIF of the signing key, and the base64 signature that implementation
// returned for it. Add vectors from real wallets to testdata/bip137_vectors.json.
func TestBIP137Vectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/bip137_vectors.json")
	require.NoError(t, err)

	var vectors []struct {
		Source    string `json:"source"`
		Text      string `json:"text"`
		WIF       string `json:"wif"`
		Signature string `json:"signature"`
	}
	require.NoError(t, json.Unmarshal(raw, &vectors))
	require.NotEmpty(t, vectors)

	for _, v := range vectors {
		t.Run(v.Source, func(t *testing.T) {
			wif, err := btcutil.DecodeWIF(v.WIF)
			require.NoError(t, err)

			digest := BitcoinSignedMessageDigest(v.Text)
			pub, _, _, err := ParseBIP137Signature(v.Signature, digest)
			require.NoError(t, err)
			require.True(t, pub.IsEqual(wif.PrivKey.PubKey()), "signature must recover the WIF's key over our digest")
		})
	}
}
