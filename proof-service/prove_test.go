package proofservice

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/btcq-org/qbtc/x/qbtc/zk/zktest"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/rs/zerolog"
)

// fixed, non-secret test key
var testPrivKeyBytes = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xab,
	0x54, 0xa9, 0x8c, 0xeb, 0x1f, 0x0a, 0xd2, 0x00,
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
}

func TestGenerateProof_RejectsNonCanonicalBitcoinAddress(t *testing.T) {
	svc := &Service{logger: zerolog.Nop()}
	req := ProveRequest{
		Signature:      "H0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000=",
		BitcoinAddress: strings.ToUpper("bc1q4wr4k0uwzryx9jyss3tsd60gaulpxaggzm3mnc"),
		ClaimerAddress: "qbtc1claimer",
		UTXOs:          []types.UTXORef{{Txid: "00", Vout: 0}},
	}

	resp, status, errResp := svc.generateProof(context.Background(), req)
	if resp != nil || status != http.StatusBadRequest || errResp == nil {
		t.Fatalf("expected 400 with error, got resp=%v status=%d err=%v", resp, status, errResp)
	}
	if errResp.Code != "INVALID_REQUEST" || !strings.Contains(errResp.Details, "exactly as stored") {
		t.Fatalf("unexpected error response: %+v", errResp)
	}
}

// TestGenerateProof_RejectsBadSignatures covers the checks that run before the
// expensive prove step. The service has no proving key, so a request that got
// past them would panic instead of returning one of these errors.
func TestGenerateProof_RejectsBadSignatures(t *testing.T) {
	const (
		chainID = "qbtc-1"
		claimer = "qbtc1claimer"
	)
	priv, pub := btcec.PrivKeyFromBytes(testPrivKeyBytes)
	address := zktest.P2WPKHAddress(pub)

	sign := func(key *btcec.PrivateKey, destination string) string {
		t.Helper()
		_, signature, err := zktest.SignClaim(key, chainID, address, destination)
		if err != nil {
			t.Fatalf("sign claim: %v", err)
		}
		return signature
	}
	otherKeyBytes := append([]byte(nil), testPrivKeyBytes...)
	otherKeyBytes[31] ^= 0x01
	otherPriv, _ := btcec.PrivKeyFromBytes(otherKeyBytes)

	tests := []struct {
		name      string
		signature string
		wantCode  string
	}{
		{"missing signature", "", "INVALID_REQUEST"},
		{"not base64", "not-base64!", "INVALID_SIGNATURE"},
		{"wrong length", "AAAA", "INVALID_SIGNATURE"},
		{"signed for another destination", sign(priv, "qbtc1attacker"), "ADDRESS_MISMATCH"},
		{"signed by another key", sign(otherPriv, claimer), "ADDRESS_MISMATCH"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := &Service{logger: zerolog.Nop()}
			resp, status, errResp := svc.generateProof(context.Background(), ProveRequest{
				Signature:      tc.signature,
				BitcoinAddress: address,
				ClaimerAddress: claimer,
				ChainID:        chainID,
				UTXOs:          []types.UTXORef{{Txid: "00", Vout: 0}},
			})
			if resp != nil || status != http.StatusBadRequest || errResp == nil {
				t.Fatalf("expected 400 with error, got resp=%v status=%d err=%v", resp, status, errResp)
			}
			if errResp.Code != tc.wantCode {
				t.Fatalf("expected code %s, got %+v", tc.wantCode, errResp)
			}
		})
	}
}
