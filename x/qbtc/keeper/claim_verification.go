package keeper

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerror "github.com/cosmos/cosmos-sdk/types/errors"

	"github.com/btcq-org/qbtc/constants"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/btcq-org/qbtc/x/qbtc/zk"
)

// ClaimProofVerifyGas is the gas a claim pays for its PLONK verification when
// the ante handler has not verified it, as for a claim nested in authz
// MsgExec. A verification takes about 3 ms; secp256k1's 1,000 gas buys about
// 50 µs.
const ClaimProofVerifyGas uint64 = 60_000

// resolvedClaim is what a MsgClaimWithProof is checked against: the address
// of its first claimable UTXO and the destination the proof must name.
type resolvedClaim struct {
	btcAddress      string
	recipient       sdk.AccAddress
	recipientBech32 string
	referrer        sdk.AccAddress // nil without a referrer
	proof           []byte
	params          zk.VerificationParams
}

// resolveClaim runs the state checks of a claim, without the proof: claims
// are enabled, the verifier is loaded, and one of the referenced UTXOs exists,
// is unclaimed, has an address and has enough confirmations. The first such
// UTXO's address is the one the proof must cover. The ante handler and the
// message handler both use it, so they check the same thing.
func (k Keeper) resolveClaim(ctx sdk.Context, msg *types.MsgClaimWithProof) (*resolvedClaim, error) {
	if k.GetConfig(ctx, constants.ClaimWithProofDisabled) > 0 {
		return nil, sdkerror.ErrInvalidRequest.Wrap("ClaimWithProof feature is disabled")
	}
	// BeginBlock loads the verifier, but CheckTx can run before the first
	// block after a restart.
	if err := k.EnsureZKVerifierInitialized(ctx); err != nil {
		return nil, sdkerror.ErrInvalidRequest.Wrapf("ZK verifier not initialized: %v", err)
	}
	if !zk.IsVerifierInitialized() {
		return nil, sdkerror.ErrInvalidRequest.Wrap("ZK verifier not initialized")
	}

	minConfirmations := k.GetConfig(ctx, constants.MinUtxoConfirmationBlocks)
	lastProcessedBlock, err := k.GetLastProcessedBlock(ctx)
	if err != nil {
		return nil, sdkerror.ErrUnknownRequest.Wrapf("failed to get last processed block: %v", err)
	}

	claimerAddr, err := sdk.AccAddressFromBech32(msg.Claimer)
	if err != nil {
		return nil, sdkerror.ErrInvalidAddress.Wrapf("invalid claimer address: %v", err)
	}
	// The receiver overrides the claimer when set.
	claim := &resolvedClaim{recipient: claimerAddr, recipientBech32: msg.Claimer}
	if msg.Receiver != "" {
		receiverAddr, err := sdk.AccAddressFromBech32(msg.Receiver)
		if err != nil {
			return nil, sdkerror.ErrInvalidAddress.Wrapf("invalid receiver address: %v", err)
		}
		claim.recipient = receiverAddr
		claim.recipientBech32 = msg.Receiver
	}
	// The optional referrer; ValidateBasic has checked it is canonical and not
	// the destination.
	if msg.Referrer != "" {
		claim.referrer, err = sdk.AccAddressFromBech32(msg.Referrer)
		if err != nil {
			return nil, sdkerror.ErrInvalidAddress.Wrapf("invalid referrer address: %v", err)
		}
	}

	for i, utxoRef := range msg.Utxos {
		utxo, err := k.Utxoes.Get(ctx, getUTXOKey(utxoRef.Txid, utxoRef.Vout))
		if err != nil {
			continue // Skip non-existent UTXOs
		}
		if utxo.EntitledAmount == 0 {
			continue // Skip already claimed UTXOs
		}
		if utxo.ScriptPubKey == nil || utxo.ScriptPubKey.Address == "" {
			continue // Skip UTXOs without address
		}
		if minConfirmations > 0 && utxo.BlockHeight > 0 && lastProcessedBlock < utxo.BlockHeight+uint64(minConfirmations) {
			continue // Skip UTXOs that have not reached the minimum confirmation threshold
		}
		if _, err := zk.BitcoinAddressToHash160(utxo.ScriptPubKey.Address); err != nil {
			continue // Skip UTXOs with invalid addresses
		}
		claim.btcAddress = utxo.ScriptPubKey.Address
		ctx.Logger().Debug("using UTXO for proof verification",
			"index", i,
			"txid", utxoRef.Txid,
			"vout", utxoRef.Vout,
			"btc_address", claim.btcAddress,
		)
		break
	}
	if claim.btcAddress == "" {
		return nil, sdkerror.ErrInvalidRequest.Wrap("no valid claimable UTXOs found")
	}

	claim.proof, err = hex.DecodeString(msg.Proof)
	if err != nil {
		return nil, sdkerror.ErrInvalidRequest.Wrapf("proof verification failed: proof data is not valid hex: %v", err)
	}
	// The claimer supplies SHA256 of their SEC-compressed pubkey; the verifier
	// natively checks RIPEMD160 of it matches the UTXO's address. ValidateBasic
	// has already enforced the hex/length shape.
	pubKeyHashBytes, err := hex.DecodeString(msg.PubKeyHashSha256)
	if err != nil || len(pubKeyHashBytes) != sha256.Size {
		return nil, sdkerror.ErrInvalidRequest.Wrap("proof verification failed: pub_key_hash_sha256 is not 32 bytes of hex")
	}
	var pubKeyHashSHA256 [32]byte
	copy(pubKeyHashSHA256[:], pubKeyHashBytes)

	// The signed claim message names recipientBech32 as destination and
	// msg.Referrer as referrer, so the proof binds to where the coins actually
	// go and to who referred the claim.
	claim.params = zk.VerificationParams{
		ChainID:          ctx.ChainID(),
		BitcoinAddress:   claim.btcAddress,
		QBTCAddress:      claim.recipientBech32,
		Referrer:         msg.Referrer,
		PubKeyHashSHA256: pubKeyHashSHA256,
	}
	return claim, nil
}

// verifyClaimProof verifies the claim's PLONK proof.
func verifyClaimProof(claim *resolvedClaim) error {
	if err := zk.VerifyProofGlobal(claim.proof, claim.params); err != nil {
		return sdkerror.ErrInvalidRequest.Wrapf("proof verification failed: %v", err)
	}
	return nil
}

// verifiedClaimKey is the context key under which the ante handler records the
// claim whose proof it verified.
type verifiedClaimKey struct{}

// withVerifiedClaim records in ctx that claim's proof has been verified, so
// the message handler does not verify it a second time.
func withVerifiedClaim(ctx sdk.Context, claim *resolvedClaim) sdk.Context {
	return ctx.WithValue(verifiedClaimKey{}, claim.digest())
}

// isVerifiedClaim reports whether ctx records claim, with the same proof and
// verification inputs, as verified.
func isVerifiedClaim(ctx sdk.Context, claim *resolvedClaim) bool {
	digest, ok := ctx.Value(verifiedClaimKey{}).([sha256.Size]byte)
	return ok && digest == claim.digest()
}

// digest commits to the proof and every verification input.
func (c *resolvedClaim) digest() [sha256.Size]byte {
	h := sha256.New()
	for _, field := range [][]byte{
		c.proof,
		[]byte(c.params.ChainID),
		[]byte(c.params.BitcoinAddress),
		[]byte(c.params.QBTCAddress),
		[]byte(c.params.Referrer),
		c.params.PubKeyHashSHA256[:],
	} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(field)))
		h.Write(n[:])
		h.Write(field)
	}
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ClaimProofDecorator verifies the proof of a free claim transaction in the
// ante handler, so CheckTx drops an invalid claim before it reaches a block,
// and a claim that fails rolls back the account FreeClaimDecorator created.
// It must run after signature verification.
//
//   - CheckTx, simulation and FinalizeBlock: the state checks and the proof.
//     FinalizeBlock cannot skip the proof, because a proposer can include
//     transactions that never went through an honest mempool. The message
//     handler then skips its own verification.
//   - ReCheckTx: the state checks only, so a claim whose UTXOs an earlier block
//     claimed leaves the mempool. The proof's validity cannot change.
//
// A claim nested in authz MsgExec does not reach this decorator; the message
// handler verifies it and charges ClaimProofVerifyGas.
type ClaimProofDecorator struct {
	k *Keeper
}

func NewClaimProofDecorator(k *Keeper) ClaimProofDecorator {
	return ClaimProofDecorator{k: k}
}

func (d ClaimProofDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	if !types.IsClaimOnlyTx(tx) {
		return next(ctx, tx, simulate)
	}
	// FreeClaimDecorator allows exactly one message in a free claim tx.
	msgs := tx.GetMsgs()
	if len(msgs) != 1 {
		return ctx, sdkerror.ErrInvalidRequest.Wrap("free-claim tx must contain exactly one MsgClaimWithProof")
	}
	msg := msgs[0].(*types.MsgClaimWithProof)

	claim, err := d.k.resolveClaim(ctx, msg)
	if err != nil {
		return ctx, err
	}
	if ctx.IsReCheckTx() {
		return next(ctx, tx, simulate)
	}
	if err := verifyClaimProof(claim); err != nil {
		return ctx, err
	}
	return next(withVerifiedClaim(ctx, claim), tx, simulate)
}
