package zk

import (
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/require"
)

const (
	testChainID     = "qbtc-1"
	testQBTCAddress = "qbtc1testaddress"
)

func p2pkhAddressForTest(pub *btcec.PublicKey) string {
	addr, err := btcutil.NewAddressPubKeyHash(btcutil.Hash160(pub.SerializeCompressed()), &chaincfg.MainNetParams)
	if err != nil {
		panic(err)
	}
	return addr.EncodeAddress()
}

func p2wpkhAddressForTest(pub *btcec.PublicKey) string {
	addr, err := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(pub.SerializeCompressed()), &chaincfg.MainNetParams)
	if err != nil {
		panic(err)
	}
	return addr.EncodeAddress()
}

func TestClaimMessageText_Layout(t *testing.T) {
	require.Equal(t, "qbtc-claim-v1", ClaimMessageVersion)
	text := ClaimMessageText("qbtc-1", "bc1qexample", "qbtc1dest", "")
	require.Equal(t, "qbtc-claim-v1|qbtc-1|bc1qexample|qbtc1dest", text, "no referrer leaves the field out")
	text = ClaimMessageText("qbtc-1", "bc1qexample", "qbtc1dest", "qbtc1referrer")
	require.Equal(t, "qbtc-claim-v1|qbtc-1|bc1qexample|qbtc1dest|qbtc1referrer", text)
}

// TestBitcoinSignedMessageDigest_MatchesBIP137 recomputes the digest by hand:
// SHA256d(0x18 || "Bitcoin Signed Message:\n" || compactSize(len) || text).
func TestBitcoinSignedMessageDigest_MatchesBIP137(t *testing.T) {
	short := ClaimMessageText(testChainID, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", testQBTCAddress, "")
	long := strings.Repeat("x", 300) // needs a 3-byte compactSize (0xfd ll hh)

	for _, text := range []string{short, long} {
		var preimage []byte
		preimage = append(preimage, 0x18)
		preimage = append(preimage, []byte("Bitcoin Signed Message:\n")...)
		switch n := len(text); {
		case n < 0xfd:
			preimage = append(preimage, byte(n))
		default:
			preimage = append(preimage, 0xfd, byte(n), byte(n>>8))
		}
		preimage = append(preimage, []byte(text)...)
		first := sha256.Sum256(preimage)
		want := sha256.Sum256(first[:])

		require.Equal(t, want, BitcoinSignedMessageDigest(text))
	}
}

// TestClaimMessageText_UnreferredMatchesLegacyText pins that a claim without a
// referrer signs the four-field text signers used before referrals existed.
func TestClaimMessageText_UnreferredMatchesLegacyText(t *testing.T) {
	legacy := strings.Join([]string{ClaimMessageVersion, testChainID, "bc1qaddress", testQBTCAddress}, "|")
	require.Equal(t, legacy, ClaimMessageText(testChainID, "bc1qaddress", testQBTCAddress, ""))
	require.Equal(t, BitcoinSignedMessageDigest(legacy), ClaimMessageDigest(testChainID, "bc1qaddress", testQBTCAddress, ""))
	require.NotEqual(t, BitcoinSignedMessageDigest(legacy+"|"), ClaimMessageDigest(testChainID, "bc1qaddress", testQBTCAddress, ""),
		"an empty referrer adds no field")
}

func TestClaimMessageDigest_BindsEveryField(t *testing.T) {
	base := ClaimMessageDigest(testChainID, "bc1qaddress", testQBTCAddress, "")
	require.Equal(t, base, ClaimMessageDigest(testChainID, "bc1qaddress", testQBTCAddress, ""), "deterministic")
	require.NotEqual(t, base, ClaimMessageDigest("other-chain-1", "bc1qaddress", testQBTCAddress, ""), "chain ID")
	require.NotEqual(t, base, ClaimMessageDigest(testChainID, "bc1qother", testQBTCAddress, ""), "bitcoin address")
	require.NotEqual(t, base, ClaimMessageDigest(testChainID, "bc1qaddress", "qbtc1attacker", ""), "destination")
	require.NotEqual(t, base, ClaimMessageDigest(testChainID, "bc1qaddress", testQBTCAddress, "qbtc1referrer"), "referrer")
	require.NotEqual(t,
		ClaimMessageDigest(testChainID, "bc1qaddress", testQBTCAddress, "qbtc1referrer"),
		ClaimMessageDigest(testChainID, "bc1qaddress", testQBTCAddress, "qbtc1attacker"), "referrer swap")
	require.NotEqual(t, base, BitcoinSignedMessageDigest(strings.Join([]string{testChainID, "bc1qaddress", testQBTCAddress}, "|")), "version token")
}

func TestParseBIP137Signature_RecoversSigner(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	digest := ClaimMessageDigest(testChainID, p2wpkhAddressForTest(priv.PubKey()), testQBTCAddress, "")
	compact := btcecdsa.SignCompact(priv, digest[:], true)
	recID := (compact[0] - 27) & 3

	// Every compressed header range (P2PKH 31..34, P2SH-P2WPKH 35..38,
	// P2WPKH 39..42) must recover the same key: wallets disagree on which to
	// use, and only the recovery id matters.
	for _, base := range []byte{31, 35, 39} {
		sig := append([]byte(nil), compact...)
		sig[0] = base + recID
		pub, r, s, err := ParseBIP137Signature(base64.StdEncoding.EncodeToString(sig), digest)
		require.NoError(t, err, "header %d", sig[0])
		require.True(t, pub.IsEqual(priv.PubKey()), "header %d", sig[0])
		require.Equal(t, new(big.Int).SetBytes(compact[1:33]), r)
		require.Equal(t, new(big.Int).SetBytes(compact[33:65]), s)
	}

	// Surrounding whitespace, as pasted from a wallet dialog, is tolerated.
	_, _, _, err = ParseBIP137Signature("  "+base64.StdEncoding.EncodeToString(compact)+"\n", digest)
	require.NoError(t, err)

	// A different digest recovers a different key (or fails outright).
	other := ClaimMessageDigest(testChainID, p2wpkhAddressForTest(priv.PubKey()), "qbtc1attacker", "")
	pub, _, _, err := ParseBIP137Signature(base64.StdEncoding.EncodeToString(compact), other)
	if err == nil {
		require.False(t, pub.IsEqual(priv.PubKey()))
	}
}

func TestParseBIP137Signature_Rejects(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	digest := ClaimMessageDigest(testChainID, p2pkhAddressForTest(priv.PubKey()), testQBTCAddress, "")
	compact := btcecdsa.SignCompact(priv, digest[:], true)
	withHeader := func(h byte) string {
		sig := append([]byte(nil), compact...)
		sig[0] = h
		return base64.StdEncoding.EncodeToString(sig)
	}

	cases := map[string]struct {
		sig  string
		want string
	}{
		"not base64":        {"not base64!", "base64"},
		"too short":         {base64.StdEncoding.EncodeToString(compact[:64]), "65 bytes"},
		"too long":          {base64.StdEncoding.EncodeToString(append(compact, 0)), "65 bytes"},
		"header below 27":   {withHeader(26), "outside the BIP-137 range"},
		"header above 42":   {withHeader(43), "outside the BIP-137 range"},
		"uncompressed (27)": {withHeader(27), "uncompressed"},
		"uncompressed (30)": {withHeader(30), "uncompressed"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, _, err := ParseBIP137Signature(tc.sig, digest)
			require.ErrorContains(t, err, tc.want)
		})
	}

	t.Run("zero r", func(t *testing.T) {
		sig := append([]byte(nil), compact...)
		for i := 1; i < 33; i++ {
			sig[i] = 0
		}
		_, _, _, err := ParseBIP137Signature(base64.StdEncoding.EncodeToString(sig), digest)
		require.Error(t, err)
	})
}

func TestCheckPubKeyOwnsAddress(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	other, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	pub := priv.PubKey()

	require.NoError(t, CheckPubKeyOwnsAddress(pub, p2pkhAddressForTest(pub)))
	require.NoError(t, CheckPubKeyOwnsAddress(pub, p2wpkhAddressForTest(pub)))
	require.ErrorContains(t, CheckPubKeyOwnsAddress(other.PubKey(), p2wpkhAddressForTest(pub)), "does not belong")
	require.Error(t, CheckPubKeyOwnsAddress(pub, "bc1pzz3q5v6l0fjwp9z4lk8mqrn0hvh5n3j7y5aa9jq4fcrqzs2k8e5sl0thmr"), "taproot unsupported")
	require.Error(t, CheckPubKeyOwnsAddress(pub, "not-an-address"))
}
