package qclient_test

import (
	"context"
	"testing"

	"cosmossdk.io/math"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/stretchr/testify/require"

	"github.com/btcq-org/qbtc/bifrost/qclient"
	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// Attestations sign the uncompressed block commit; both bifrost checks must
// verify them against it, not against the compressed BlockContent.
func TestAttestationsSignTheUncompressedCommit(t *testing.T) {
	coinbase := wire.NewMsgTx(2)
	coinbase.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{}, wire.MaxPrevOutIndex), []byte{0x01, 0x02}, nil))
	coinbase.AddTxOut(wire.NewTxOut(312_500_000, []byte{0x51}))
	block := wire.NewMsgBlock(&wire.BlockHeader{Version: 4})
	require.NoError(t, block.AddTransaction(coinbase))
	commit, err := types.NewBtcBlockCommit(block)
	require.NoError(t, err)
	signBytes, content, err := types.EncodeBtcBlockCommit(commit)
	require.NoError(t, err)

	priv := ed25519.GenPrivKey()
	validator, err := stakingtypes.NewValidator(sdk.ValAddress(priv.PubKey().Address()).String(), priv.PubKey(), stakingtypes.Description{})
	require.NoError(t, err)
	validator.Status = stakingtypes.Bonded
	validator.Tokens = math.NewInt(10_000_000)
	client, err := qclient.New("localhost:9090", true, "http://localhost:26657")
	require.NoError(t, err)
	client = client.WithStakingClient(&mockStakingClient{validators: []stakingtypes.Validator{validator}, bondedTokens: validator.Tokens})
	consAddr := sdk.ConsAddress(priv.PubKey().Address()).String()

	attest := func(signed []byte) *types.Attestation {
		sig, err := priv.Sign(signed)
		require.NoError(t, err)
		return &types.Attestation{Address: consAddr, Signature: sig}
	}
	msg := func(att *types.Attestation) *types.MsgBtcBlock {
		return &types.MsgBtcBlock{Height: 1, Hash: block.BlockHash().String(), BlockContent: content, Attestations: []*types.Attestation{att}}
	}
	gossip := func(att *types.Attestation) types.BlockGossip {
		return types.BlockGossip{Height: 1, Hash: block.BlockHash().String(), BlockContent: content, Attestation: att}
	}

	ctx := context.Background()
	require.NoError(t, client.VerifyAttestation(ctx, gossip(attest(signBytes))))
	require.NoError(t, client.CheckAttestationsSuperMajority(ctx, msg(attest(signBytes))))

	require.Error(t, client.VerifyAttestation(ctx, gossip(attest(content))))
	require.Error(t, client.CheckAttestationsSuperMajority(ctx, msg(attest(content))))
}
