// Package main generates a valid proof-service request for testing.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/btcq-org/qbtc/x/qbtc/zk"
	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// Request matches the proof-service ProveRequest structure
type Request struct {
	SignatureR     string          `json:"signature_r"`
	SignatureS     string          `json:"signature_s"`
	PublicKey      string          `json:"public_key"`
	UTXOs          []types.UTXORef `json:"utxos"`
	ClaimerAddress string          `json:"claimer_address"`
	ChainID        string          `json:"chain_id"`
}

func main() {
	// dummy private key
	privateKeyHex := "0000000000000000000000000000000000000000000000ab54a98ceb1f0ad2"
	claimerAddress := "qbtc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpz7s0q"
	chainID := "qbtc-1"
	sampleTxID := "0000000000000000000000000000000000000000000000000000000000000000"

	// Allow override via env vars
	if pk := os.Getenv("PRIVATE_KEY"); pk != "" {
		privateKeyHex = pk
	}
	if addr := os.Getenv("CLAIMER_ADDRESS"); addr != "" {
		claimerAddress = addr
	}
	if cid := os.Getenv("CHAIN_ID"); cid != "" {
		chainID = cid
	}

	// Load private key
	pkBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid private key hex: %v\n", err)
		os.Exit(1)
	}
	privKey, pubKey := btcec.PrivKeyFromBytes(pkBytes)

	// Get compressed public key
	compressedPubKey := pubKey.SerializeCompressed()
	fmt.Fprintf(os.Stderr, "Public Key: %s\n", hex.EncodeToString(compressedPubKey))

	// Compute address hash (Hash160 of compressed pubkey)
	addressHash, err := zk.PublicKeyToAddressHash(compressedPubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to compute address hash: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Address Hash: %s\n", hex.EncodeToString(addressHash[:]))

	// Compute QBTC address hash
	qbtcAddressHash := zk.HashQBTCAddress(claimerAddress)
	fmt.Fprintf(os.Stderr, "QBTC Address Hash: %s\n", hex.EncodeToString(qbtcAddressHash[:]))

	// Compute chain ID hash
	chainIDHash := zk.ComputeChainIDHash(chainID)
	fmt.Fprintf(os.Stderr, "Chain ID Hash: %s\n", hex.EncodeToString(chainIDHash[:]))

	// Compute the message hash that needs to be signed
	messageHash := zk.ComputeClaimMessage(addressHash, qbtcAddressHash, chainIDHash)
	fmt.Fprintf(os.Stderr, "Message Hash: %s\n", hex.EncodeToString(messageHash[:]))

	// Sign the message
	sig := btcecdsa.Sign(privKey, messageHash[:])

	// Parse R and S from DER signature
	sigBytes := sig.Serialize()
	rLen := int(sigBytes[3])
	rBytes := sigBytes[4 : 4+rLen]
	sLen := int(sigBytes[4+rLen+1])
	sBytes := sigBytes[4+rLen+2 : 4+rLen+2+sLen]

	// Remove leading zero bytes (DER uses signed integers)
	if len(rBytes) > 0 && rBytes[0] == 0 {
		rBytes = rBytes[1:]
	}
	if len(sBytes) > 0 && sBytes[0] == 0 {
		sBytes = sBytes[1:]
	}

	// Pad to 32 bytes
	rPadded := make([]byte, 32)
	sPadded := make([]byte, 32)
	copy(rPadded[32-len(rBytes):], rBytes)
	copy(sPadded[32-len(sBytes):], sBytes)

	// Build the request
	req := Request{
		SignatureR: hex.EncodeToString(rPadded),
		SignatureS: hex.EncodeToString(sPadded),
		PublicKey:  hex.EncodeToString(compressedPubKey),
		UTXOs: []types.UTXORef{
			{Txid: sampleTxID, Vout: 1},
		},
		ClaimerAddress: claimerAddress,
		ChainID:        chainID,
	}

	// Output JSON to stdout
	output, err := json.MarshalIndent(req, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(output))

	fmt.Fprintln(os.Stderr, "\n--- Usage ---")
	fmt.Fprintln(os.Stderr, "curl -X POST http://localhost:8090/prove -H 'Content-Type: application/json' -d '<output above>'")
}
