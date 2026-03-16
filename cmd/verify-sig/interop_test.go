package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/stretchr/testify/require"
	mldsaSession "github.com/vultisig/go-wrappers/mldsa"
)

func prepareIDs(n int) []byte {
	keys := []string{}
	for p := 1; p <= n; p++ {
		keys = append(keys, fmt.Sprintf("p%d", p))
	}
	return []byte(strings.Join(keys, "\x00"))
}

type party struct {
	session mldsaSession.Handle
	id      string
}

func doKeygen(t *testing.T, level mldsaSession.SecurityLevel, threshold, n int) []mldsaSession.Handle {
	ids := prepareIDs(n)
	setupMsg, err := mldsaSession.MldsaKeygenSetupMsgNew(level, threshold, nil, ids)
	require.NoError(t, err)

	parties := make([]party, n)
	for i := 1; i <= n; i++ {
		id := fmt.Sprintf("p%d", i)
		session, err := mldsaSession.MldsaKeygenSessionFromSetup(level, setupMsg, []byte(id))
		require.NoError(t, err)
		parties[i-1] = party{session: session, id: id}
	}

	msgq := make(map[string][][]byte)
	var handles []mldsaSession.Handle
	for len(handles) != n {
		for _, p := range parties {
			for {
				buf, err := mldsaSession.MldsaKeygenSessionOutputMessage(p.session)
				require.NoError(t, err)
				if buf == nil {
					break
				}
				for idx := 0; idx < n; idx++ {
					recv, err := mldsaSession.MldsaKeygenSessionMessageReceiver(p.session, buf, idx)
					require.NoError(t, err)
					if recv == "" {
						break
					}
					msgq[recv] = append(msgq[recv], buf)
				}
			}
		}
		for _, p := range parties {
			for _, msg := range msgq[p.id] {
				fin, err := mldsaSession.MldsaKeygenSessionInputMessage(p.session, msg)
				require.NoError(t, err)
				if fin {
					h, err := mldsaSession.MldsaKeygenSessionFinish(p.session)
					require.NoError(t, err)
					handles = append(handles, h)
				}
			}
			msgq[p.id] = nil
		}
	}
	return handles
}

func doSign(t *testing.T, level mldsaSession.SecurityLevel, shares []mldsaSession.Handle, msg []byte) []byte {
	threshold := len(shares)
	ids := prepareIDs(threshold)
	keyID, err := mldsaSession.MldsaKeyshareKeyID(shares[0])
	if err != nil {
		t.Logf("doSign: keyID error: %v", err)
		return nil
	}

	setupMsg, err := mldsaSession.MldsaSignSetupMsgNew(level, keyID, "m", msg, ids)
	if err != nil {
		t.Logf("doSign: setup error: %v", err)
		return nil
	}

	parties := make([]party, threshold)
	for i := 0; i < threshold; i++ {
		id := fmt.Sprintf("p%d", i+1)
		session, err := mldsaSession.MldsaSignSessionFromSetup(level, setupMsg, []byte(id), shares[i])
		if err != nil {
			t.Logf("doSign: session error: %v", err)
			return nil
		}
		parties[i] = party{session: session, id: id}
	}

	msgq := make(map[string][][]byte)
	var sigs [][]byte
	for len(sigs) != threshold {
		for _, p := range parties {
			for {
				buf, err := mldsaSession.MldsaSignSessionOutputMessage(p.session)
				if err != nil {
					t.Logf("doSign: output error: %v", err)
					return nil
				}
				if buf == nil {
					break
				}
				for idx := 0; idx < threshold; idx++ {
					recv, err := mldsaSession.MldsaSignSessionMessageReceiver(p.session, buf, idx)
					if err != nil {
						return nil
					}
					if recv == "" {
						break
					}
					msgq[recv] = append(msgq[recv], buf)
				}
			}
		}
		for _, p := range parties {
			for _, m := range msgq[p.id] {
				fin, err := mldsaSession.MldsaSignSessionInputMessage(p.session, m)
				if err != nil {
					t.Logf("doSign: input error: %v", err)
					return nil
				}
				if fin {
					sig, err := mldsaSession.MldsaSignSessionFinish(p.session)
					if err != nil {
						t.Logf("doSign: finish error: %v", err)
						return nil
					}
					sigs = append(sigs, sig)
				}
			}
			msgq[p.id] = nil
		}
	}
	return sigs[0]
}

// TestMLDSAInterop tests whether vscore TSS signatures verify with cloudflare/circl.
func TestMLDSAInterop(t *testing.T) {
	shares := doKeygen(t, mldsaSession.MlDsa44, 2, 2)
	require.Len(t, shares, 2)

	pubKeyBytes, err := mldsaSession.MldsaKeysharePublicKey(shares[0])
	require.NoError(t, err)
	t.Logf("PubKey: %d bytes (circl expects %d)", len(pubKeyBytes), mldsa44.PublicKeySize)

	var msgHash [32]byte
	rand.Read(msgHash[:])

	var sig []byte
	for attempt := 0; attempt < 30; attempt++ {
		// Re-generate shares each attempt to avoid stale state
		if attempt > 0 {
			shares = doKeygen(t, mldsaSession.MlDsa44, 2, 2)
		}
		result := doSign(t, mldsaSession.MlDsa44, shares, msgHash[:])
		if result != nil {
			sig = result
			t.Logf("Signing succeeded on attempt %d", attempt)
			break
		}
		t.Logf("attempt %d: reject sampling, retrying with new keys", attempt)
	}
	require.NotNil(t, sig, "signing should succeed within 30 attempts")
	t.Logf("Signature: %d bytes (circl expects %d)", len(sig), mldsa44.SignatureSize)

	// Verify with cloudflare/circl
	scheme := mldsa44.Scheme()
	publicKey, err := scheme.UnmarshalBinaryPublicKey(pubKeyBytes)
	require.NoError(t, err, "circl should unmarshal the pubkey")

	// Test 1: raw message (what TSS signed)
	r1 := scheme.Verify(publicKey, msgHash[:], sig, nil)
	t.Logf("Verify(msgHash, sig)         = %v", r1)

	// Test 2: SHA256(message) - what cosmos-sdk does
	sha := sha256.Sum256(msgHash[:])
	r2 := scheme.Verify(publicKey, sha[:], sig, nil)
	t.Logf("Verify(SHA256(msg), sig)     = %v", r2)

	if r1 {
		t.Log("SUCCESS: vscore sigs verify with circl (raw)")
	} else if r2 {
		t.Log("SUCCESS: vscore sigs verify with circl (SHA256)")
	} else {
		t.Error("FAIL: vscore MLDSA-44 signatures are NOT interoperable with cloudflare/circl")
	}
}
