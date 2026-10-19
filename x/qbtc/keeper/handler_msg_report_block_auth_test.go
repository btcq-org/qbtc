package keeper_test

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/cometbft/cometbft/crypto"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	"github.com/btcq-org/qbtc/x/qbtc/types"
)

const (
	authTestHeight   = 800000
	authTestInput    = "1111111111111111111111111111111111111111111111111111111111111111"
	authTestCoinbase = "cbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcb"
	authTestSpend    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func authTestBlockHash(height uint64) string {
	return fmt.Sprintf("%064x", height)
}

func authTestVout(n uint32, sats int64) btcjson.Vout {
	return btcjson.Vout{
		Value: btcutil.Amount(sats).ToBTC(),
		N:     n,
		ScriptPubKey: btcjson.ScriptPubKeyResult{
			Type:    "pubkeyhash",
			Address: "1J6QsrCXRTZusGEeyg44BcoqgM4SZXTXhC",
		},
	}
}

// authTestBlock is a block at authTestHeight with a coinbase and one
// transaction that spends authTestInput (preloaded by the test).
func authTestBlock() btcjson.GetBlockVerboseTxResult {
	return btcjson.GetBlockVerboseTxResult{
		Hash:   authTestBlockHash(authTestHeight),
		Height: authTestHeight,
		Tx: []btcjson.TxRawResult{
			{
				Txid: authTestCoinbase,
				Vin:  []btcjson.Vin{{Coinbase: "03abcdef"}},
				Vout: []btcjson.Vout{authTestVout(0, 312_500_000)},
			},
			{
				Txid: authTestSpend,
				Vin:  []btcjson.Vin{{Txid: authTestInput, Vout: 0}},
				Vout: []btcjson.Vout{authTestVout(0, 90_000)},
			},
		},
	}
}

// attestedBlockMsg returns a MsgBtcBlock for block, attested by the fixture's
// only validator and signed by the injection signer, with the given unsigned
// height and hash.
func attestedBlockMsg(t *testing.T, f *fixture, block btcjson.GetBlockVerboseTxResult, height uint64, hash string) *types.MsgBtcBlock {
	t.Helper()
	content, err := json.Marshal(block)
	require.NoError(t, err)
	compressed, err := types.GzipDeterministic(content, gzip.BestCompression)
	require.NoError(t, err)
	address, err := f.GetConsensusAddress()
	require.NoError(t, err)
	signature, err := f.privateKey.Sign(compressed)
	require.NoError(t, err)
	return &types.MsgBtcBlock{
		Height:       height,
		Hash:         hash,
		BlockContent: compressed,
		Attestations: []*types.Attestation{{Address: address, Signature: signature}},
		Signer:       types.EBifrostSignerAddress,
	}
}

func setupAuthTest(t *testing.T) *fixture {
	t.Helper()
	f := initFixture(t)
	f.bankKeeper.EXPECT().MintCoins(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	input := types.UTXO{
		Txid:           authTestInput,
		Vout:           0,
		Amount:         100_000,
		EntitledAmount: 100_000,
		ScriptPubKey:   &types.ScriptPubKeyResult{Type: "pubkeyhash", Address: "1J6QsrCXRTZusGEeyg44BcoqgM4SZXTXhC"},
	}
	require.NoError(t, f.keeper.Utxoes.Set(f.ctx, input.GetKey(), input))
	return f
}

func authTestEntitlement(t *testing.T, f *fixture, txid string) uint64 {
	t.Helper()
	utxo, err := f.keeper.Utxoes.Get(f.ctx, fmt.Sprintf("%s-0", txid))
	require.NoError(t, err)
	return utxo.EntitledAmount
}

func authTestLastProcessed(t *testing.T, f *fixture) uint64 {
	t.Helper()
	h, err := f.keeper.GetLastProcessedBlock(f.ctx)
	require.NoError(t, err)
	return h
}

// The signer constant must be the hash-derived address, not one anyone holds a key for.
func TestEBifrostSignerAddressIsHashDerived(t *testing.T) {
	require.Equal(t, sdk.AccAddress(crypto.AddressHash([]byte("ebifrost_signer"))).String(), types.EBifrostSignerAddress)
}

func TestSetMsgReportBlock_RejectsOtherSigner(t *testing.T) {
	f := setupAuthTest(t)
	msg := attestedBlockMsg(t, f, authTestBlock(), authTestHeight, authTestBlockHash(authTestHeight))
	signer, err := f.GetRandomQbtcAddress()
	require.NoError(t, err)
	msg.Signer = signer

	_, err = keeper.NewMsgServerImpl(f.keeper).SetMsgReportBlock(f.ctx, msg)
	require.ErrorContains(t, err, "injection path")
	require.Zero(t, authTestLastProcessed(t, f))
}

// Attested content must not apply at any height other than its own.
func TestSetMsgReportBlock_RejectsContentAtAnotherHeight(t *testing.T) {
	f := setupAuthTest(t)
	server := keeper.NewMsgServerImpl(f.keeper)
	_, err := server.SetMsgReportBlock(f.ctx, attestedBlockMsg(t, f, authTestBlock(), authTestHeight, authTestBlockHash(authTestHeight)))
	require.NoError(t, err)
	require.NoError(t, f.keeper.ClaimUTXO(f.ctx, authTestCoinbase, 0, nil))

	for name, hash := range map[string]string{
		"original hash": authTestBlockHash(authTestHeight),
		"next hash":     authTestBlockHash(authTestHeight + 1),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := server.SetMsgReportBlock(f.ctx, attestedBlockMsg(t, f, authTestBlock(), authTestHeight+1, hash))
			require.ErrorContains(t, err, "does not match")
			require.Equal(t, uint64(authTestHeight), authTestLastProcessed(t, f))
			require.Zero(t, authTestEntitlement(t, f, authTestCoinbase), "claimed coinbase must stay claimed")
			require.Equal(t, uint64(90_000), authTestEntitlement(t, f, authTestSpend), "unspent output must keep its entitlement")
		})
	}
}

func TestSetMsgReportBlock_RejectsHashMismatch(t *testing.T) {
	f := setupAuthTest(t)
	msg := attestedBlockMsg(t, f, authTestBlock(), authTestHeight, authTestBlockHash(authTestHeight+7))
	_, err := keeper.NewMsgServerImpl(f.keeper).SetMsgReportBlock(f.ctx, msg)
	require.ErrorContains(t, err, "does not match")
	require.Zero(t, authTestLastProcessed(t, f))
}

func TestSetMsgReportBlock_RejectsHeightThatIsNotNext(t *testing.T) {
	f := setupAuthTest(t)
	server := keeper.NewMsgServerImpl(f.keeper)
	_, err := server.SetMsgReportBlock(f.ctx, attestedBlockMsg(t, f, authTestBlock(), authTestHeight, authTestBlockHash(authTestHeight)))
	require.NoError(t, err)

	block := authTestBlock()
	block.Height = authTestHeight + 2
	block.Hash = authTestBlockHash(authTestHeight + 2)
	_, err = server.SetMsgReportBlock(f.ctx, attestedBlockMsg(t, f, block, authTestHeight+2, block.Hash))
	require.ErrorContains(t, err, "not the next block height")
	require.Equal(t, uint64(authTestHeight), authTestLastProcessed(t, f))
}

// Processing the same outputs twice must fail instead of overwriting UTXOs.
func TestSetMsgReportBlock_DoesNotOverwriteUTXOs(t *testing.T) {
	f := setupAuthTest(t)
	server := keeper.NewMsgServerImpl(f.keeper)
	msg := attestedBlockMsg(t, f, authTestBlock(), authTestHeight, authTestBlockHash(authTestHeight))
	_, err := server.SetMsgReportBlock(f.ctx, msg)
	require.NoError(t, err)
	require.NoError(t, f.keeper.ClaimUTXO(f.ctx, authTestCoinbase, 0, nil))

	// Rewind the height so the same block passes the height check again.
	require.NoError(t, f.keeper.LastProcessedBlock.Set(f.ctx, authTestHeight-1))
	_, err = server.SetMsgReportBlock(f.ctx, msg)
	require.ErrorContains(t, err, "already exists")
	require.Zero(t, authTestEntitlement(t, f, authTestCoinbase))
	require.Equal(t, uint64(90_000), authTestEntitlement(t, f, authTestSpend))
}
