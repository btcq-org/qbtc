package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"

	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/btcq-org/qbtc/x/qbtc/zk"
	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// claimTarget is what the user is claiming and where the coins go. The
// destination of the signed message is the receiver when set, else the claimer.
type claimTarget struct {
	chainID        string
	bitcoinAddress string
	claimer        string
	receiver       string
	utxos          []types.UTXORef
}

func (c claimTarget) destination() string {
	if c.receiver != "" {
		return c.receiver
	}
	return c.claimer
}

func (c claimTarget) messageText() string {
	return zk.ClaimMessageText(c.chainID, c.bitcoinAddress, c.destination())
}

func (c claimTarget) digest() [32]byte {
	return zk.BitcoinSignedMessageDigest(c.messageText())
}

// parseUTXORef parses "txid:vout".
func parseUTXORef(s string) (types.UTXORef, error) {
	txid, voutStr, ok := strings.Cut(s, ":")
	if !ok || txid == "" {
		return types.UTXORef{}, fmt.Errorf("--utxo must be txid:vout, got %q", s)
	}
	if _, err := hex.DecodeString(txid); err != nil || len(txid) != 64 {
		return types.UTXORef{}, fmt.Errorf("--utxo txid must be 64 hex characters, got %q", txid)
	}
	vout, err := strconv.ParseUint(voutStr, 10, 32)
	if err != nil {
		return types.UTXORef{}, fmt.Errorf("--utxo vout must be a non-negative integer, got %q", voutStr)
	}
	return types.UTXORef{Txid: txid, Vout: uint32(vout)}, nil
}

// signatureFromWallet turns a base64 BIP-137 signature pasted from a wallet
// into prover input.
func signatureFromWallet(target claimTarget, sigBase64 string) (zk.ProofParams, *btcec.PublicKey, error) {
	digest := target.digest()
	pub, r, s, err := zk.ParseBIP137Signature(sigBase64, digest)
	if err != nil {
		return zk.ProofParams{}, nil, err
	}
	return zk.ProofParamsFromSignature(pub, r, s, digest), pub, nil
}

// signatureFromTSS asks a TSS signer for an ECDSA signature over the claim
// digest and checks it natively before the expensive prove step.
func signatureFromTSS(target claimTarget, tssURL string) (zk.ProofParams, *btcec.PublicKey, error) {
	digest := target.digest()
	signResp, err := requestTSSSignature(tssURL, digest)
	if err != nil {
		return zk.ProofParams{}, nil, fmt.Errorf("failed to get TSS signature: %w", err)
	}

	rBytes, err := hex.DecodeString(signResp.Signature.R)
	if err != nil {
		return zk.ProofParams{}, nil, fmt.Errorf("invalid signature R: %w", err)
	}
	sBytes, err := hex.DecodeString(signResp.Signature.S)
	if err != nil {
		return zk.ProofParams{}, nil, fmt.Errorf("invalid signature S: %w", err)
	}
	pubKeyBytes, err := hex.DecodeString(signResp.PublicKey)
	if err != nil {
		return zk.ProofParams{}, nil, fmt.Errorf("invalid public key: %w", err)
	}
	pub, err := btcec.ParsePubKey(pubKeyBytes)
	if err != nil {
		return zk.ProofParams{}, nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	var r, s btcec.ModNScalar
	if r.SetByteSlice(padTo32Bytes(rBytes)) || s.SetByteSlice(padTo32Bytes(sBytes)) {
		return zk.ProofParams{}, nil, fmt.Errorf("TSS signature scalar is not below the curve order")
	}
	if !btcecdsa.NewSignature(&r, &s).Verify(digest[:], pub) {
		return zk.ProofParams{}, nil, fmt.Errorf("TSS signature does not verify against its public key and the claim message")
	}

	return zk.ProofParamsFromSignature(pub,
		new(big.Int).SetBytes(padTo32Bytes(rBytes)),
		new(big.Int).SetBytes(padTo32Bytes(sBytes)),
		digest), pub, nil
}

// buildClaimMsg assembles the message `qbtcd tx qbtc claim-with-proof` submits.
// broadcaster is left empty so the CLI fills it from --from.
func buildClaimMsg(target claimTarget, proof []byte, pubKeyHashSHA256 [32]byte) *types.MsgClaimWithProof {
	return &types.MsgClaimWithProof{
		Claimer:          target.claimer,
		Receiver:         target.receiver,
		Utxos:            target.utxos,
		Proof:            hex.EncodeToString(proof),
		PubKeyHashSha256: hex.EncodeToString(pubKeyHashSHA256[:]),
	}
}

// claimMsgJSON encodes the message exactly as the chain CLI expects to read
// it: proto field names, nothing extra.
func claimMsgJSON(msg *types.MsgClaimWithProof) ([]byte, error) {
	return json.MarshalIndent(msg, "", "  ")
}

// TSSSignRequest is the request body for the TSS /sign endpoint. The TSS signs
// the 32-byte BIP-137 claim digest as-is.
type TSSSignRequest struct {
	MessageHash string `json:"message_hash"`
}

// TSSSignatureData contains the ECDSA signature components from TSS
type TSSSignatureData struct {
	R string `json:"r"`
	S string `json:"s"`
	V int    `json:"v"`
}

// TSSSignResponse is the response from the TSS /sign endpoint
type TSSSignResponse struct {
	Signature TSSSignatureData `json:"signature"`
	PublicKey string           `json:"public_key"`
}

// requestTSSSignature requests a signature over digest from the TSS signer.
func requestTSSSignature(tssURL string, digest [32]byte) (*TSSSignResponse, error) {
	reqBytes, err := json.Marshal(TSSSignRequest{MessageHash: hex.EncodeToString(digest[:])})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := http.Post(tssURL+"/sign", "application/json", bytes.NewReader(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("TSS returned error: %s", string(respBody))
	}

	var signResp TSSSignResponse
	if err := json.Unmarshal(respBody, &signResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &signResp, nil
}

// padTo32Bytes left-pads a big-endian scalar to 32 bytes.
func padTo32Bytes(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}
