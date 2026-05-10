package keeper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// btcHeaderSize is the canonical Bitcoin block header wire size in bytes.
const btcHeaderSize = 80

// hashSize is the size of a Bitcoin double-SHA256 hash.
const hashSize = 32

// SerializeHeader writes the 80-byte canonical Bitcoin wire encoding of h.
// Field order: version (4) | prev_block (32) | merkle_root (32) | timestamp (4)
// | bits (4) | nonce (4). All multi-byte integers are little-endian; prev_block
// and merkle_root are little-endian byte streams as they appear on the wire.
func SerializeHeader(h *types.BtcHeader) ([]byte, error) {
	if h == nil {
		return nil, fmt.Errorf("nil header")
	}
	if len(h.PrevBlock) != hashSize {
		return nil, fmt.Errorf("prev_block must be %d bytes, got %d", hashSize, len(h.PrevBlock))
	}
	if len(h.MerkleRoot) != hashSize {
		return nil, fmt.Errorf("merkle_root must be %d bytes, got %d", hashSize, len(h.MerkleRoot))
	}
	out := make([]byte, btcHeaderSize)
	binary.LittleEndian.PutUint32(out[0:4], h.Version)
	copy(out[4:36], h.PrevBlock)
	copy(out[36:68], h.MerkleRoot)
	binary.LittleEndian.PutUint32(out[68:72], h.Timestamp)
	binary.LittleEndian.PutUint32(out[72:76], h.Bits)
	binary.LittleEndian.PutUint32(out[76:80], h.Nonce)
	return out, nil
}

// HeaderHash returns dsha256(serialize(h)), the canonical Bitcoin block hash
// (in the same little-endian byte order Bitcoin uses for prev_block links).
func HeaderHash(h *types.BtcHeader) ([hashSize]byte, error) {
	bz, err := SerializeHeader(h)
	if err != nil {
		return [hashSize]byte{}, err
	}
	return DoubleSHA256(bz), nil
}

// DoubleSHA256 returns SHA256(SHA256(b)), Bitcoin's standard hash function.
func DoubleSHA256(b []byte) [hashSize]byte {
	first := sha256.Sum256(b)
	return sha256.Sum256(first[:])
}

// BitsToTarget expands the 32-bit compact difficulty representation into the
// 256-bit numeric target used by Bitcoin's proof-of-work check.
//
// The compact format encodes a base-256 floating-point number: the high byte
// is the exponent and the low 24 bits are the (signed) mantissa. We reject
// negative mantissas and overflow on conversion since neither is reachable
// from a valid Bitcoin header.
func BitsToTarget(bits uint32) (*big.Int, error) {
	exponent := bits >> 24
	mantissa := bits & 0x007fffff
	negative := bits&0x00800000 != 0
	if negative {
		return nil, fmt.Errorf("negative bits mantissa")
	}
	if mantissa == 0 {
		return new(big.Int), nil
	}
	target := new(big.Int).SetUint64(uint64(mantissa))
	if exponent <= 3 {
		target.Rsh(target, uint(8*(3-exponent)))
	} else {
		target.Lsh(target, uint(8*(exponent-3)))
	}
	// Reject targets that overflow 256 bits; max valid target fits in 32 bytes.
	if target.BitLen() > 256 {
		return nil, fmt.Errorf("target overflow")
	}
	return target, nil
}

// CheckProofOfWork verifies that headerHash, interpreted as a big-endian
// integer (Bitcoin convention reverses the wire bytes for numeric comparison),
// is less than or equal to the target derived from bits.
func CheckProofOfWork(headerHash [hashSize]byte, bits uint32) error {
	target, err := BitsToTarget(bits)
	if err != nil {
		return err
	}
	if target.Sign() <= 0 {
		return fmt.Errorf("invalid bits target")
	}
	// Bitcoin compares the hash as a big-endian integer; the wire/header form
	// is little-endian, so reverse before SetBytes.
	reversed := make([]byte, hashSize)
	for i := 0; i < hashSize; i++ {
		reversed[i] = headerHash[hashSize-1-i]
	}
	hashInt := new(big.Int).SetBytes(reversed)
	if hashInt.Cmp(target) > 0 {
		return fmt.Errorf("proof-of-work below target")
	}
	return nil
}

// MerkleRoot computes the Bitcoin merkle root over the given txids. Each txid
// must be 32 bytes in Bitcoin little-endian wire format. Bitcoin duplicates
// the last leaf to pad to an even count at every level, including the leaf
// level, which is the convention this implementation follows.
func MerkleRoot(txids [][]byte) ([hashSize]byte, error) {
	var zero [hashSize]byte
	if len(txids) == 0 {
		return zero, fmt.Errorf("no txids")
	}
	level := make([][hashSize]byte, len(txids))
	for i, t := range txids {
		if len(t) != hashSize {
			return zero, fmt.Errorf("txid %d wrong length: %d", i, len(t))
		}
		copy(level[i][:], t)
	}
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		next := make([][hashSize]byte, len(level)/2)
		var buf [2 * hashSize]byte
		for i := 0; i < len(level); i += 2 {
			copy(buf[:hashSize], level[i][:])
			copy(buf[hashSize:], level[i+1][:])
			next[i/2] = DoubleSHA256(buf[:])
		}
		level = next
	}
	return level[0], nil
}

// validateBtcBlockCommit runs the full set of header-level integrity checks on
// a reported block: header round-trips to msg.Hash, the chain links to the
// last accepted header, the encoded header satisfies its declared difficulty,
// and the merkle root commits to exactly the txid list inside the commit.
//
// The function returns the validated header hash so the caller can persist it
// as the new chain tip after the rest of the block is processed successfully.
func (s *msgServer) validateBtcBlockCommit(ctx context.Context, msg *types.MsgBtcBlock) ([hashSize]byte, error) {
	if msg.Commit == nil || msg.Commit.Header == nil {
		return [hashSize]byte{}, fmt.Errorf("missing block commit or header")
	}
	if len(msg.Hash) != hashSize {
		return [hashSize]byte{}, fmt.Errorf("hash must be %d bytes, got %d", hashSize, len(msg.Hash))
	}

	headerHash, err := HeaderHash(msg.Commit.Header)
	if err != nil {
		return [hashSize]byte{}, fmt.Errorf("serialize header: %w", err)
	}
	if !bytes.Equal(headerHash[:], msg.Hash) {
		return [hashSize]byte{}, fmt.Errorf("header hash %x does not match msg.hash %x", headerHash[:], msg.Hash)
	}

	if err := CheckProofOfWork(headerHash, msg.Commit.Header.Bits); err != nil {
		return [hashSize]byte{}, fmt.Errorf("proof-of-work: %w", err)
	}

	prev, err := s.k.LastProcessedHeader.Get(ctx)
	if err != nil {
		return [hashSize]byte{}, fmt.Errorf("read last processed header: %w", err)
	}
	if !bytes.Equal(msg.Commit.Header.PrevBlock, prev) {
		return [hashSize]byte{}, fmt.Errorf("prev_block mismatch: header points to %x, last accepted %x", msg.Commit.Header.PrevBlock, prev)
	}

	// Bitcoin requires exactly one coinbase tx, at index 0. Enforcing that here
	// keeps the rest of the handler from having to defend against a multi-coinbase
	// or misplaced-coinbase commit (where, e.g., processCoinbaseVOuts would only
	// see the last one and silently lose entitlement on the others).
	txids := make([][]byte, len(msg.Commit.Txs))
	coinbaseCount := 0
	for i, tx := range msg.Commit.Txs {
		if tx == nil {
			return [hashSize]byte{}, fmt.Errorf("tx %d nil", i)
		}
		if tx.Coinbase {
			coinbaseCount++
			if i != 0 {
				return [hashSize]byte{}, fmt.Errorf("coinbase tx must be at index 0, got %d", i)
			}
		} else if i == 0 {
			return [hashSize]byte{}, fmt.Errorf("first tx must be coinbase")
		}
		if len(tx.Txid) != hashSize {
			return [hashSize]byte{}, fmt.Errorf("tx %d txid wrong length: %d", i, len(tx.Txid))
		}
		txids[i] = tx.Txid
	}
	if coinbaseCount != 1 {
		return [hashSize]byte{}, fmt.Errorf("expected exactly 1 coinbase tx, got %d", coinbaseCount)
	}
	root, err := MerkleRoot(txids)
	if err != nil {
		return [hashSize]byte{}, fmt.Errorf("compute merkle root: %w", err)
	}
	if !bytes.Equal(root[:], msg.Commit.Header.MerkleRoot) {
		return [hashSize]byte{}, fmt.Errorf("merkle root mismatch: computed %x, header %x", root[:], msg.Commit.Header.MerkleRoot)
	}

	return headerHash, nil
}
