package zk

import (
	"bytes"
	"strings"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// ClaimMessageVersion is the first field of the claim message text. Bumping it
// invalidates every signature made under the previous text layout.
const ClaimMessageVersion = "qbtc-claim-v1"

// bitcoinSignedMessageMagic is the prefix every Bitcoin wallet prepends when
// signing a text message (BIP-137). It guarantees the signed digest can never
// be a valid transaction hash.
const bitcoinSignedMessageMagic = "Bitcoin Signed Message:\n"

// ClaimMessageText is the exact text a user signs in their Bitcoin wallet:
//
//	qbtc-claim-v1|<chain-id>|<bitcoin address>|<destination qbtc address>[|<referrer qbtc address>]
//
// The Bitcoin address must be the string stored on the UTXO being claimed,
// byte for byte. The destination is the receiver when set, else the claimer.
// The referrer is optional and its field is left out entirely when there is
// none, so a claim without a referrer signs the same four-field text as
// signers that predate referrals. Signing the referrer stops anyone who relays
// the proof from swapping it.
//
// The text parses unambiguously: no address alphabet (base58, bech32)
// contains '|', and a Bitcoin address never starts with the qbtc bech32
// prefix, so a text ends in a referrer exactly when its last two fields are
// both qbtc addresses, even if the chain ID contains '|'.
func ClaimMessageText(chainID, bitcoinAddress, qbtcAddress, referrer string) string {
	fields := []string{ClaimMessageVersion, chainID, bitcoinAddress, qbtcAddress}
	if referrer != "" {
		fields = append(fields, referrer)
	}
	return strings.Join(fields, "|")
}

// BitcoinSignedMessageDigest returns the BIP-137 digest of text:
//
//	SHA256d(varstr("Bitcoin Signed Message:\n") || varstr(text))
//
// This is the value Bitcoin Core, Electrum, Sparrow, Ledger and Trezor sign
// for a message, and the ECDSA message scalar the claim circuit verifies.
func BitcoinSignedMessageDigest(text string) [32]byte {
	var buf bytes.Buffer
	// bytes.Buffer writes never fail.
	_ = wire.WriteVarString(&buf, 0, bitcoinSignedMessageMagic)
	_ = wire.WriteVarString(&buf, 0, text)
	var digest [32]byte
	copy(digest[:], chainhash.DoubleHashB(buf.Bytes()))
	return digest
}

// ClaimMessageDigest returns the digest the claim signature must cover. The
// verifier recomputes it natively from on-chain data, which binds the proof to
// the chain, the Bitcoin address being claimed, the destination address and
// the referrer.
func ClaimMessageDigest(chainID, bitcoinAddress, qbtcAddress, referrer string) [32]byte {
	return BitcoinSignedMessageDigest(ClaimMessageText(chainID, bitcoinAddress, qbtcAddress, referrer))
}
