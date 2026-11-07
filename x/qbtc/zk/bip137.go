package zk

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
)

const (
	bip137SignatureLength = 65

	// BIP-137 header byte ranges. Each range spans the four recovery ids.
	bip137HeaderMin           = 27 // P2PKH, uncompressed key
	bip137HeaderCompressedMin = 31 // P2PKH, compressed key
	bip137HeaderMax           = 42 // P2WPKH (39..42); 35..38 is P2SH-P2WPKH
	bip137RecoveryIDMask      = 3
)

// ParseBIP137Signature decodes a base64 BIP-137 message signature, as produced
// by a wallet's "sign message" feature, and recovers the signing public key for
// digest. It returns the key and the raw (r, s) scalars the claim circuit needs.
//
// Wallets disagree on which header range to use for segwit addresses, so every
// header from 31 to 42 is accepted and only its recovery id is used. Headers
// 27 to 30 announce an uncompressed public key; those are rejected because the
// circuit commits to the 33-byte compressed encoding.
func ParseBIP137Signature(sigBase64 string, digest [32]byte) (*btcec.PublicKey, *big.Int, *big.Int, error) {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigBase64))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("signature is not valid base64: %w", err)
	}
	if len(sig) != bip137SignatureLength {
		return nil, nil, nil, fmt.Errorf("signature must be %d bytes, got %d", bip137SignatureLength, len(sig))
	}

	header := sig[0]
	switch {
	case header < bip137HeaderMin || header > bip137HeaderMax:
		return nil, nil, nil, fmt.Errorf("signature header byte %d is outside the BIP-137 range %d..%d", header, bip137HeaderMin, bip137HeaderMax)
	case header < bip137HeaderCompressedMin:
		return nil, nil, nil, fmt.Errorf("signature was made with an uncompressed public key; only addresses derived from a compressed key can be claimed")
	}

	compact := make([]byte, bip137SignatureLength)
	copy(compact, sig)
	compact[0] = bip137HeaderCompressedMin + ((header - bip137HeaderMin) & bip137RecoveryIDMask)

	pub, _, err := btcecdsa.RecoverCompact(compact, digest[:])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to recover public key from signature: %w", err)
	}

	r := new(big.Int).SetBytes(sig[1:33])
	s := new(big.Int).SetBytes(sig[33:65])
	return pub, r, s, nil
}

// ProofParamsFromSignature packs a recovered or TSS-provided ECDSA signature
// into the prover's input.
func ProofParamsFromSignature(pub *btcec.PublicKey, r, s *big.Int, digest [32]byte) ProofParams {
	return ProofParams{
		SignatureR:  r,
		SignatureS:  s,
		PublicKeyX:  pub.X(),
		PublicKeyY:  pub.Y(),
		MessageHash: digest,
	}
}

// CheckPubKeyOwnsAddress returns an error unless bitcoinAddress is the P2PKH or
// P2WPKH address of pub's compressed encoding.
func CheckPubKeyOwnsAddress(pub *btcec.PublicKey, bitcoinAddress string) error {
	want, err := BitcoinAddressToHash160(bitcoinAddress)
	if err != nil {
		return err
	}
	got := btcutil.Hash160(pub.SerializeCompressed())
	if !bytes.Equal(got, want[:]) {
		return fmt.Errorf("public key does not belong to %s", bitcoinAddress)
	}
	return nil
}
