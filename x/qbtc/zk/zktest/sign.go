// Package zktest signs claim messages with a local Bitcoin key for tests and
// demos. Production users sign in their wallet or TSS instead.
package zktest

import (
	"encoding/base64"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"

	"github.com/btcq-org/qbtc/x/qbtc/zk"
)

// SignClaim signs the claim message for (chainID, bitcoinAddress, qbtcAddress)
// the way a wallet would: a BIP-137 compact signature over the message digest,
// base64 encoded. The signature is then run through zk.ParseBIP137Signature so
// callers exercise the production parser. It returns the prover input and the
// base64 signature.
func SignClaim(priv *btcec.PrivateKey, chainID, bitcoinAddress, qbtcAddress string) (zk.ProofParams, string, error) {
	digest := zk.ClaimMessageDigest(chainID, bitcoinAddress, qbtcAddress)
	sigBase64 := base64.StdEncoding.EncodeToString(btcecdsa.SignCompact(priv, digest[:], true))

	pub, r, s, err := zk.ParseBIP137Signature(sigBase64, digest)
	if err != nil {
		return zk.ProofParams{}, "", fmt.Errorf("parse signature: %w", err)
	}
	if !pub.IsEqual(priv.PubKey()) {
		return zk.ProofParams{}, "", fmt.Errorf("recovered public key does not match the signing key")
	}
	return zk.ProofParamsFromSignature(pub, r, s, digest), sigBase64, nil
}

// P2PKHAddress returns the mainnet P2PKH address of pub's compressed encoding.
func P2PKHAddress(pub *btcec.PublicKey) string {
	addr, err := btcutil.NewAddressPubKeyHash(btcutil.Hash160(pub.SerializeCompressed()), &chaincfg.MainNetParams)
	if err != nil {
		panic(err) // Hash160 is always 20 bytes
	}
	return addr.EncodeAddress()
}

// P2WPKHAddress returns the mainnet P2WPKH address of pub's compressed encoding.
func P2WPKHAddress(pub *btcec.PublicKey) string {
	addr, err := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(pub.SerializeCompressed()), &chaincfg.MainNetParams)
	if err != nil {
		panic(err) // Hash160 is always 20 bytes
	}
	return addr.EncodeAddress()
}
