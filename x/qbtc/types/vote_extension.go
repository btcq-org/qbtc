package types

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

const (
	// MaxBtcBlockVotes is the maximum number of Bitcoin blocks a vote extension
	// attests, and so the maximum number of blocks in a MsgBtcBlock.
	MaxBtcBlockVotes = 8

	// MaxVoteExtensionSize caps the size of a vote extension in bytes. Each vote
	// is below 120 bytes, so the cap leaves room for MaxBtcBlockVotes votes.
	MaxVoteExtensionSize = 2048

	// BtcCommitHashSize is the size of BtcBlockVote.CommitHash.
	BtcCommitHashSize = sha256.Size

	// btcBlockHashLen is the length of a Bitcoin block hash in hex.
	btcBlockHashLen = 64
)

// BtcCommitHash returns the hash validators attest for a block: the SHA-256 of
// the uncompressed encoding of its BtcBlockCommit.
func BtcCommitHash(signBytes []byte) [BtcCommitHashSize]byte {
	return sha256.Sum256(signBytes)
}

// ValidateFormat checks the shape of a vote extension without looking at any
// Bitcoin state: the number of votes, distinct heights, hash formats.
func (e *BtcBlockVoteExtension) ValidateFormat() error {
	if len(e.Votes) > MaxBtcBlockVotes {
		return fmt.Errorf("%d votes, maximum is %d", len(e.Votes), MaxBtcBlockVotes)
	}
	seen := make(map[uint64]struct{}, len(e.Votes))
	for i, vote := range e.Votes {
		if vote == nil {
			return fmt.Errorf("vote %d is empty", i)
		}
		if _, dup := seen[vote.Height]; dup {
			return fmt.Errorf("height %d is voted twice", vote.Height)
		}
		seen[vote.Height] = struct{}{}
		if len(vote.CommitHash) != BtcCommitHashSize {
			return fmt.Errorf("vote %d: commit hash is %d bytes, want %d", i, len(vote.CommitHash), BtcCommitHashSize)
		}
		if !isLowerHex(vote.Hash, btcBlockHashLen) {
			return fmt.Errorf("vote %d: hash %q is not %d lowercase hex characters", i, vote.Hash, btcBlockHashLen)
		}
	}
	return nil
}

func isLowerHex(s string, length int) bool {
	if len(s) != length {
		return false
	}
	return !strings.ContainsFunc(s, func(r rune) bool {
		return (r < '0' || r > '9') && (r < 'a' || r > 'f')
	})
}
