package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// Test private key (DO NOT use in production)
const testPrivateKeyHex = "0000000000000000000000000000000000000000000000000000000000001234"

func TestNewTSSEmulator(t *testing.T) {
	t.Run("valid private key", func(t *testing.T) {
		emulator, err := NewTSSEmulator(testPrivateKeyHex)
		require.NoError(t, err)
		require.NotNil(t, emulator)
		require.NotNil(t, emulator.privateKey)
		require.NotNil(t, emulator.publicKey)
	})

	t.Run("invalid hex", func(t *testing.T) {
		_, err := NewTSSEmulator("not-hex")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid private key hex")
	})

	t.Run("wrong length", func(t *testing.T) {
		_, err := NewTSSEmulator("1234") // Only 2 bytes
		require.Error(t, err)
		require.Contains(t, err.Error(), "must be 32 bytes")
	})
}

func TestSign(t *testing.T) {
	emulator, err := NewTSSEmulator(testPrivateKeyHex)
	require.NoError(t, err)

	t.Run("valid message hash", func(t *testing.T) {
		messageHash := sha256.Sum256([]byte("test message"))
		resp, err := emulator.Sign(messageHash[:])
		require.NoError(t, err)
		require.NotNil(t, resp)

		// Verify response structure
		require.NotEmpty(t, resp.Signature.R)
		require.NotEmpty(t, resp.Signature.S)
		require.NotEmpty(t, resp.PublicKey)
		require.True(t, resp.Signature.V == 0 || resp.Signature.V == 1)

		// Verify R and S are valid hex
		rBytes, err := hex.DecodeString(resp.Signature.R)
		require.NoError(t, err)
		require.NotEmpty(t, rBytes)

		sBytes, err := hex.DecodeString(resp.Signature.S)
		require.NoError(t, err)
		require.NotEmpty(t, sBytes)

		// Verify public key is valid compressed format (33 bytes)
		pubKeyBytes, err := hex.DecodeString(resp.PublicKey)
		require.NoError(t, err)
		require.Len(t, pubKeyBytes, 33)
	})

	t.Run("wrong message hash length", func(t *testing.T) {
		shortHash := []byte("too short")
		_, err := emulator.Sign(shortHash)
		require.Error(t, err)
		require.Contains(t, err.Error(), "must be 32 bytes")
	})

	t.Run("deterministic signatures for same input", func(t *testing.T) {
		messageHash := sha256.Sum256([]byte("reproducible test"))
		resp1, err := emulator.Sign(messageHash[:])
		require.NoError(t, err)

		resp2, err := emulator.Sign(messageHash[:])
		require.NoError(t, err)

		// Same message should produce same R (S might differ due to k generation)
		// Note: btcec uses RFC 6979 for deterministic k, so signature should be same
		require.Equal(t, resp1.Signature.R, resp2.Signature.R)
		require.Equal(t, resp1.Signature.S, resp2.Signature.S)
		require.Equal(t, resp1.PublicKey, resp2.PublicKey)
	})
}

func TestGetPublicKeyHash(t *testing.T) {
	emulator, err := NewTSSEmulator(testPrivateKeyHex)
	require.NoError(t, err)

	hash := emulator.GetPublicKeyHash()
	require.Len(t, hash, 20, "Hash160 should be 20 bytes")
}

func TestSignHTTPHandler(t *testing.T) {
	emulator, err := NewTSSEmulator(testPrivateKeyHex)
	require.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleSign(w, r, emulator)
	})

	t.Run("successful signing", func(t *testing.T) {
		messageHash := sha256.Sum256([]byte("test"))
		reqBody := SignRequest{MessageHash: hex.EncodeToString(messageHash[:])}
		bodyBytes, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/sign", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp SignResponse
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)
		require.NotEmpty(t, resp.Signature.R)
		require.NotEmpty(t, resp.Signature.S)
		require.NotEmpty(t, resp.PublicKey)
	})

	t.Run("method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/sign", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/sign", bytes.NewReader([]byte("not json")))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Contains(t, rec.Body.String(), "invalid JSON")
	})

	t.Run("invalid hex in message_hash", func(t *testing.T) {
		reqBody := SignRequest{MessageHash: "not-valid-hex"}
		bodyBytes, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/sign", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Contains(t, rec.Body.String(), "invalid message_hash hex")
	})

	t.Run("wrong length message_hash", func(t *testing.T) {
		reqBody := SignRequest{MessageHash: "1234"} // Only 2 bytes
		bodyBytes, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/sign", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Contains(t, rec.Body.String(), "must be 32 bytes")
	})
}

func TestHash160(t *testing.T) {
	// Test known vector
	data := []byte{0x02, 0x03} // Example compressed public key prefix bytes
	hash := hash160(data)
	require.Len(t, hash, 20)

	// Hash should be deterministic
	hash2 := hash160(data)
	require.Equal(t, hash, hash2)
}


