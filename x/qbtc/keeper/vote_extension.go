package keeper

import (
	"bytes"
	"context"

	abci "github.com/cometbft/cometbft/abci/types"
	cmtprotocrypto "github.com/cometbft/cometbft/proto/tendermint/crypto"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/baseapp"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerror "github.com/cosmos/cosmos-sdk/types/errors"

	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// GetPubKeyByConsAddr lets the keeper satisfy baseapp.ValidatorStore so it can
// be passed directly to baseapp.ValidateVoteExtensions.
func (k Keeper) GetPubKeyByConsAddr(ctx context.Context, addr sdk.ConsAddress) (cmtprotocrypto.PublicKey, error) {
	return k.stakingKeeper.GetPubKeyByConsAddr(ctx, addr)
}

var _ baseapp.ValidatorStore = Keeper{}

// ValidateInjectedBtcBlock verifies that the injected Bitcoin block delta is
// backed by a >2/3 voting-power supermajority that attested its digest through
// CometBFT vote extensions. It performs three checks:
//
//  1. baseapp.ValidateVoteExtensions: every extension signature is valid and the
//     extended commit matches the canonical last commit (authenticity).
//  2. a tally of the (now-trusted) extensions has >2/3 power agreeing on the
//     same (block hash, delta hash) for this height.
//  3. the injected delta bytes hash to the attested delta digest, and its block
//     hash matches the attested hash (integrity).
//
// It is the single authoritative attestation check, run by every validator
// during FinalizeBlock (and pre-checked in ProcessProposal).
func (k Keeper) ValidateInjectedBtcBlock(ctx sdk.Context, msg *types.MsgInjectBtcBlock) error {
	if msg == nil || msg.Delta == nil {
		return sdkerror.ErrInvalidRequest.Wrap("nil injected btc block")
	}

	var extCommit abci.ExtendedCommitInfo
	if err := extCommit.Unmarshal(msg.ExtendedCommitInfo); err != nil {
		return sdkerror.ErrInvalidRequest.Wrapf("failed to unmarshal extended commit info: %v", err)
	}

	// currentHeight and chainID are ignored by ValidateVoteExtensions (it reads
	// them from ctx); pass zero values per the SDK contract.
	if err := baseapp.ValidateVoteExtensions(ctx, k, 0, "", extCommit); err != nil {
		return sdkerror.ErrUnauthorized.Wrapf("invalid vote extensions: %v", err)
	}

	blockHash, deltaHash, power, totalPower := TallyBtcBlockDelta(extCommit, uint64(msg.Delta.Height))
	// strict >2/3: power*3 > totalPower*2
	if totalPower == 0 || power*3 <= totalPower*2 {
		return sdkerror.ErrUnauthorized.Wrapf("insufficient attestation power: %d of %d", power, totalPower)
	}

	if !bytes.Equal(deltaHash, msg.Delta.Digest()) {
		return sdkerror.ErrUnauthorized.Wrap("injected delta does not match attested digest")
	}
	if !bytes.Equal(blockHash, msg.Delta.BlockHash) {
		return sdkerror.ErrUnauthorized.Wrap("injected delta block hash does not match attested hash")
	}
	return nil
}

// TallyBtcBlockDelta sums voting power per (block hash, delta hash) across the
// commit-vote extensions for targetHeight and returns the winning digest with
// its power and the total committed power. Callers must run
// baseapp.ValidateVoteExtensions first so the extensions are authenticated.
func TallyBtcBlockDelta(extCommit abci.ExtendedCommitInfo, targetHeight uint64) (blockHash, deltaHash []byte, power, totalPower int64) {
	type digest struct{ hash, delta string }
	powerByDigest := make(map[digest]int64)
	bytesByDigest := make(map[digest]struct{ hash, delta []byte })

	for _, vote := range extCommit.Votes {
		totalPower += vote.Validator.Power
		if vote.BlockIdFlag != cmtproto.BlockIDFlagCommit || len(vote.VoteExtension) == 0 {
			continue
		}
		var ve types.BtcBlockVoteExtension
		if err := ve.Unmarshal(vote.VoteExtension); err != nil {
			continue
		}
		seen := false
		for _, item := range ve.Items {
			if item.Height != targetHeight {
				continue
			}
			// Count a validator at most once for this height.
			if seen {
				break
			}
			seen = true
			d := digest{hash: string(item.BlockHash), delta: string(item.DeltaHash)}
			powerByDigest[d] += vote.Validator.Power
			bytesByDigest[d] = struct{ hash, delta []byte }{item.BlockHash, item.DeltaHash}
		}
	}

	var best digest
	for d, p := range powerByDigest {
		if p > power || (p == power && (best.hash == "" || d.hash < best.hash)) {
			power = p
			best = d
		}
	}
	if power > 0 {
		blockHash = bytesByDigest[best].hash
		deltaHash = bytesByDigest[best].delta
	}
	return blockHash, deltaHash, power, totalPower
}
