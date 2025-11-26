//go:build ignore

// This is a utility script to dump DKLS keyshares and signatures.
// Run with: go run -tags=testing ./cmd/dkls-tss/dkls_dump.go
package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	session "github.com/vultisig/go-wrappers/go-dkls/sessions"
)

func prepareIDSlice(n int) []byte {
	keys := make([]string, n)
	for p := 1; p <= n; p++ {
		keys[p-1] = fmt.Sprintf("p%d", p)
	}
	return []byte(strings.Join(keys, "\x00"))
}

type Participant struct {
	Session session.Handle
	ID      string
}

func runKeygen(t, n int) ([]session.Handle, error) {
	ids := prepareIDSlice(n)
	setupMsg, err := session.DklsKeygenSetupMsgNew(t, nil, ids)
	if err != nil {
		return nil, err
	}

	parties := make([]Participant, n)
	for i := 1; i <= n; i++ {
		id := fmt.Sprintf("p%d", i)
		sessionHandle, err := session.DklsKeygenSessionFromSetup(setupMsg, []byte(id))
		if err != nil {
			return nil, err
		}
		parties[i-1] = Participant{Session: sessionHandle, ID: id}
	}

	msgq := make(map[string][][]byte)
	shares := make([]session.Handle, 0, n)

	for len(shares) != n {
		for _, party := range parties {
			for {
				buf, err := session.DklsKeygenSessionOutputMessage(party.Session)
				if err != nil {
					return nil, err
				}
				if buf == nil {
					break
				}
				for idx := 0; idx < n; idx++ {
					receiver, err := session.DklsKeygenSessionMessageReceiver(party.Session, buf, idx)
					if err != nil {
						return nil, err
					}
					if receiver == "" {
						break
					}
					msgq[receiver] = append(msgq[receiver], buf)
				}
			}
		}

		for _, party := range parties {
			for _, msg := range msgq[party.ID] {
				finished, err := session.DklsKeygenSessionInputMessage(party.Session, msg)
				if err != nil {
					return nil, err
				}
				if finished {
					share, err := session.DklsKeygenSessionFinish(party.Session)
					if err != nil {
						return nil, err
					}
					shares = append(shares, share)
					_ = session.DklsKeygenSessionFree(party.Session)
				}
			}
			msgq[party.ID] = nil
		}
	}

	return shares, nil
}

func runSign(shares []session.Handle, msg []byte) ([][]byte, error) {
	t := len(shares)
	keyID, err := session.DklsKeyshareKeyID(shares[0])
	if err != nil {
		return nil, err
	}

	ids := prepareIDSlice(t)
	setup, err := session.DklsSignSetupMsgNew(keyID, nil, msg, ids)
	if err != nil {
		return nil, err
	}

	parties := make([]Participant, t)
	for i := 1; i <= t; i++ {
		id := fmt.Sprintf("p%d", i)
		sessionHandle, err := session.DklsSignSessionFromSetup(setup, []byte(id), shares[i-1])
		if err != nil {
			return nil, err
		}
		parties[i-1] = Participant{Session: sessionHandle, ID: id}
	}

	msgq := make(map[string][][]byte)
	signatures := make([][]byte, 0, t)

	for len(signatures) != t {
		for _, party := range parties {
			for {
				buf, err := session.DklsSignSessionOutputMessage(party.Session)
				if err != nil {
					return nil, err
				}
				if len(buf) == 0 {
					break
				}
				for idx := 0; idx < t; idx++ {
					receiver, err := session.DklsSignSessionMessageReceiver(party.Session, buf, idx)
					if err != nil {
						return nil, err
					}
					if len(receiver) == 0 {
						break
					}
					msgq[string(receiver)] = append(msgq[string(receiver)], buf)
				}
			}
		}

		for _, party := range parties {
			for _, msg := range msgq[party.ID] {
				finished, err := session.DklsSignSessionInputMessage(party.Session, msg)
				if err != nil {
					return nil, err
				}
				if finished {
					sig, err := session.DklsSignSessionFinish(party.Session)
					if err != nil {
						return nil, err
					}
					signatures = append(signatures, sig)
					_ = session.DklsSignSessionFree(party.Session)
				}
			}
			msgq[party.ID] = nil
		}
	}

	return signatures, nil
}

func main() {
	fmt.Println("=== DKLS Keyshare and Signature Dump ===\n")

	// Run 2-of-2 keygen
	fmt.Println("Running 2-of-2 DKLS keygen...")
	keyshares, err := runKeygen(2, 2)
	if err != nil {
		log.Fatal(err)
	}

	// Get public key
	pubKey, err := session.DklsKeysharePublicKey(keyshares[0])
	if err != nil {
		log.Fatal(err)
	}

	// Get key ID
	keyID, err := session.DklsKeyshareKeyID(keyshares[0])
	if err != nil {
		log.Fatal(err)
	}

	// Serialize keyshares to bytes
	keyshare1Bytes, err := session.DklsKeyshareToBytes(keyshares[0])
	if err != nil {
		log.Fatal(err)
	}
	keyshare2Bytes, err := session.DklsKeyshareToBytes(keyshares[1])
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("\n========== KEYGEN OUTPUT ==========")
	fmt.Printf("Shared Public Key (33 bytes, compressed):\n%s\n\n", hex.EncodeToString(pubKey))
	fmt.Printf("Key ID (32 bytes):\n%s\n\n", hex.EncodeToString(keyID))
	fmt.Printf("Keyshare 1 size: %d bytes\n", len(keyshare1Bytes))
	fmt.Printf("Keyshare 2 size: %d bytes\n", len(keyshare2Bytes))

	// Save keyshares to files
	os.WriteFile("/tmp/dkls_keyshare_1.bin", keyshare1Bytes, 0644)
	os.WriteFile("/tmp/dkls_keyshare_2.bin", keyshare2Bytes, 0644)
	fmt.Println("\nKeyshares saved to /tmp/dkls_keyshare_1.bin and /tmp/dkls_keyshare_2.bin")

	// Create a test message to sign
	message := []byte("Hello from DKLS TSS! This is a test message.")
	// Hash it to 32 bytes (simulating what would happen with a real message)
	var msgHash [32]byte
	copy(msgHash[:], message)
	for i := len(message); i < 32; i++ {
		msgHash[i] = 0
	}

	fmt.Println("\n========== SIGNING ==========")
	fmt.Printf("Message (raw): %s\n", string(message))
	fmt.Printf("Message hash (32 bytes):\n%s\n\n", hex.EncodeToString(msgHash[:]))

	// Sign the message
	fmt.Println("Running 2-of-2 DKLS signing...")
	signatures, err := runSign(keyshares, msgHash[:])
	if err != nil {
		log.Fatal(err)
	}

	sig := signatures[0]
	fmt.Println("\n========== SIGNATURE OUTPUT ==========")
	fmt.Printf("Signature (65 bytes: R[32] || S[32] || V[1]):\n%s\n\n", hex.EncodeToString(sig))
	fmt.Printf("R (32 bytes): %s\n", hex.EncodeToString(sig[:32]))
	fmt.Printf("S (32 bytes): %s\n", hex.EncodeToString(sig[32:64]))
	fmt.Printf("V (recovery): %d\n", sig[64])

	// Save signature to file
	os.WriteFile("/tmp/dkls_signature.bin", sig, 0644)
	fmt.Println("\nSignature saved to /tmp/dkls_signature.bin")

	// Print first 200 bytes of keyshare 1 as hex (for viewing)
	fmt.Println("\n========== KEYSHARE 1 PREVIEW (first 200 bytes) ==========")
	previewLen := 200
	if len(keyshare1Bytes) < previewLen {
		previewLen = len(keyshare1Bytes)
	}
	fmt.Printf("%s...\n", hex.EncodeToString(keyshare1Bytes[:previewLen]))

	// Cleanup
	for _, share := range keyshares {
		_ = session.DklsKeyshareFree(share)
	}

	fmt.Println("\n=== Done ===")
}

