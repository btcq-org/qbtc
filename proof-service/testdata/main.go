// Package main generates a valid proof-service request for testing.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/btcq-org/qbtc/x/qbtc/zk"
	"github.com/btcq-org/qbtc/x/qbtc/zk/zktest"
	"github.com/btcsuite/btcd/btcec/v2"
)

// Request matches the proof-service ProveRequest structure (wallet form).
type Request struct {
	Signature      string          `json:"signature"`
	BitcoinAddress string          `json:"bitcoin_address"`
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

	compressedPubKey := pubKey.SerializeCompressed()
	fmt.Fprintf(os.Stderr, "Public Key: %s\n", hex.EncodeToString(compressedPubKey))

	bitcoinAddress := zktest.P2WPKHAddress(pubKey)
	fmt.Fprintf(os.Stderr, "Bitcoin Address: %s\n", bitcoinAddress)
	fmt.Fprintf(os.Stderr, "Message: %s\n", zk.ClaimMessageText(chainID, bitcoinAddress, claimerAddress))

	// Sign the claim message the way a wallet would (BIP-137)
	_, signature, err := zktest.SignClaim(privKey, chainID, bitcoinAddress, claimerAddress)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to sign: %v\n", err)
		os.Exit(1)
	}

	req := Request{
		Signature:      signature,
		BitcoinAddress: bitcoinAddress,
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
