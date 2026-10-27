package keeper_test

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/cometbft/cometbft/crypto"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/btcq-org/qbtc/x/qbtc/types"
)

const authTestInput = "1111111111111111111111111111111111111111111111111111111111111111"

// setupAuthTest anchors a regtest chain at 800000 and preloads authTestInput.
func setupAuthTest(t *testing.T) (*fixture, *regtestChain) {
	t.Helper()
	f := initFixture(t)
	f.bankKeeper.EXPECT().MintCoins(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	c := newRegtestChain(t, f, 800000)
	setTestUtxo(t, f, c.params, authTestInput, 0, 100_000, 100_000)
	return f, c
}

// authTestBlock is the next block with a coinbase and one transaction that
// spends authTestInput.
func authTestBlock(t *testing.T, c *regtestChain) (*wire.MsgBlock, *wire.MsgTx, *wire.MsgTx) {
	t.Helper()
	coinbase := c.coinbase(312_500_000)
	spend := spendTx([]wire.OutPoint{outpoint(t, authTestInput, 0)}, p2pkhOut(t, 90_000))
	return c.nextBlock(coinbase, spend), coinbase, spend
}

// The signer constant must be the hash-derived address, not one anyone holds a key for.
func TestEBifrostSignerAddressIsHashDerived(t *testing.T) {
	initFixture(t) // sets the qbtc address prefix
	require.Equal(t, sdk.AccAddress(crypto.AddressHash([]byte("ebifrost_signer"))).String(), types.EBifrostSignerAddress)
}

func TestSetMsgReportBlock_RejectsOtherSigner(t *testing.T) {
	f, c := setupAuthTest(t)
	block, _, _ := authTestBlock(t, c)
	msg := attestedBlockMsg(t, f, c.height+1, block)
	signer, err := f.GetRandomQbtcAddress()
	require.NoError(t, err)
	msg.Signer = signer

	require.ErrorContains(t, submitBlockMsg(f, msg), "injection path")
	require.Equal(t, uint64(800000), getLastProcessed(t, f))
}

// An accepted block cannot be applied again at the next height: it does not
// link to the new tip.
func TestSetMsgReportBlock_RejectsBlockAtAnotherHeight(t *testing.T) {
	f, c := setupAuthTest(t)
	block, coinbase, spend := authTestBlock(t, c)
	c.mustSubmit(block)
	require.NoError(t, f.keeper.ClaimUTXO(f.ctx, coinbase.TxHash().String(), 0, nil))

	err := submitBlockMsg(f, attestedBlockMsg(t, f, c.height+1, block))
	require.ErrorContains(t, err, "not on the last processed block")
	require.Equal(t, uint64(800001), getLastProcessed(t, f))
	require.Zero(t, getTestEntitlement(t, f, coinbase.TxHash().String(), 0), "claimed coinbase must stay claimed")
	require.Equal(t, uint64(90_000), getTestEntitlement(t, f, spend.TxHash().String(), 0), "unspent output must keep its entitlement")
}

func TestSetMsgReportBlock_RejectsHashMismatch(t *testing.T) {
	f, c := setupAuthTest(t)
	block, _, _ := authTestBlock(t, c)
	msg := attestedBlockMsg(t, f, c.height+1, block)
	msg.Blocks[0].Hash = c.tip.BlockHash().String()
	attest(t, f, msg)

	require.ErrorContains(t, submitBlockMsg(f, msg), "does not match block hash")
	require.Equal(t, uint64(800000), getLastProcessed(t, f))
}

func TestSetMsgReportBlock_RejectsHeightThatIsNotNext(t *testing.T) {
	f, c := setupAuthTest(t)
	block, _, _ := authTestBlock(t, c)
	require.ErrorContains(t, submitBlockMsg(f, attestedBlockMsg(t, f, c.height+2, block)), "not the next block height")
	require.Equal(t, uint64(800000), getLastProcessed(t, f))
}

// Processing the same outputs twice must fail instead of overwriting UTXOs.
func TestSetMsgReportBlock_DoesNotOverwriteUTXOs(t *testing.T) {
	f, c := setupAuthTest(t)
	anchor := c.tip
	block, coinbase, spend := authTestBlock(t, c)
	c.mustSubmit(block)
	require.NoError(t, f.keeper.ClaimUTXO(f.ctx, coinbase.TxHash().String(), 0, nil))

	// Rewind the tip so the same block passes the height and link checks again.
	setBtcAnchor(t, f, 800000, &anchor)
	err := submitBlockMsg(f, attestedBlockMsg(t, f, 800001, block))
	require.ErrorContains(t, err, "already exists")
	require.Zero(t, getTestEntitlement(t, f, coinbase.TxHash().String(), 0))
	require.Equal(t, uint64(90_000), getTestEntitlement(t, f, spend.TxHash().String(), 0))
}

// Each rule the chain checks on a reported block, through the block handler.
func TestSetMsgReportBlock_VerifiesBlock(t *testing.T) {
	cases := []struct {
		name    string
		modify  func(t *testing.T, c *regtestChain) *types.MsgBtcBlock
		wantErr string
	}{
		{
			name: "not linked to the tip",
			modify: func(t *testing.T, c *regtestChain) *types.MsgBtcBlock {
				block := c.nextBlock(c.coinbase())
				block.Header.PrevBlock = chainhash.Hash{1}
				mineHeader(t, &block.Header, c.params)
				return attestedBlockMsg(t, c.f, c.height+1, block)
			},
			wantErr: "not on the last processed block",
		},
		{
			name: "proof of work not met",
			modify: func(t *testing.T, c *regtestChain) *types.MsgBtcBlock {
				block := c.nextBlock(c.coinbase())
				for block.Header.Nonce = 0; ; block.Header.Nonce++ {
					hash := block.Header.BlockHash()
					if hash[31] >= 0x80 { // above the regtest target 0x7fff...
						break
					}
				}
				return attestedBlockMsg(t, c.f, c.height+1, block)
			},
			wantErr: "does not meet its proof-of-work target",
		},
		{
			name: "wrong difficulty bits",
			modify: func(t *testing.T, c *regtestChain) *types.MsgBtcBlock {
				block := c.nextBlock(c.coinbase())
				block.Header.Bits = 0x1d00ffff
				return attestedBlockMsg(t, c.f, c.height+1, block)
			},
			wantErr: "difficulty bits",
		},
		{
			name: "transactions not in the merkle root",
			modify: func(t *testing.T, c *regtestChain) *types.MsgBtcBlock {
				block := c.nextBlock(c.coinbase())
				require.NoError(t, block.AddTransaction(spendTx([]wire.OutPoint{outpoint(t, authTestInput, 0)}, p2pkhOut(t, 90_000))))
				return attestedBlockMsg(t, c.f, c.height+1, block)
			},
			wantErr: "merkle root",
		},
		{
			name: "no coinbase",
			modify: func(t *testing.T, c *regtestChain) *types.MsgBtcBlock {
				return attestedBlockMsg(t, c.f, c.height+1, c.nextBlock(spendTx([]wire.OutPoint{outpoint(t, authTestInput, 0)}, p2pkhOut(t, 90_000))))
			},
			wantErr: "does not start with a coinbase",
		},
		{
			name: "second coinbase",
			modify: func(t *testing.T, c *regtestChain) *types.MsgBtcBlock {
				second := c.coinbase(1)
				second.TxIn[0].SignatureScript = append(second.TxIn[0].SignatureScript, 0x01)
				return attestedBlockMsg(t, c.f, c.height+1, c.nextBlock(c.coinbase(), second))
			},
			wantErr: "second coinbase",
		},
		{
			name: "repeated transaction",
			modify: func(t *testing.T, c *regtestChain) *types.MsgBtcBlock {
				spend := spendTx([]wire.OutPoint{outpoint(t, authTestInput, 0)}, p2pkhOut(t, 90_000))
				return attestedBlockMsg(t, c.f, c.height+1, c.nextBlock(c.coinbase(), spend, spend))
			},
			wantErr: "repeats transaction",
		},
		{
			name: "transaction not in canonical encoding",
			modify: func(t *testing.T, c *regtestChain) *types.MsgBtcBlock {
				block := c.nextBlock(c.coinbase())
				commit, err := types.NewBtcBlockCommit(block)
				require.NoError(t, err)
				commit.Txs[0] = append(commit.Txs[0], 0x00)
				_, content, err := types.EncodeBtcBlockCommit(commit)
				require.NoError(t, err)
				msg := attestedBlockMsg(t, c.f, c.height+1, block)
				msg.Blocks[0].BlockContent = content
				return attest(t, c.f, msg)
			},
			wantErr: "canonical",
		},
		{
			name: "attestation of other content",
			modify: func(t *testing.T, c *regtestChain) *types.MsgBtcBlock {
				// the votes attest one block, the message carries another
				msg := attestedBlockMsg(t, c.f, c.height+1, c.nextBlock(c.coinbase()))
				msg.Blocks[0] = blockOf(t, c.height+1, c.nextBlock(c.coinbase(1)))
				return msg
			},
			wantErr: "insufficient vote extension power",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(st *testing.T) {
			f, c := setupAuthTest(st)
			require.ErrorContains(st, submitBlockMsg(f, tc.modify(st, c)), tc.wantErr)
			require.Equal(st, uint64(800000), getLastProcessed(st, f))
		})
	}
}

func TestSetMsgReportBlock_RequiresAnchor(t *testing.T) {
	f := initFixture(t)
	block, height := loadMainnetBlock(t, "../../../testdata/block/300003.json")
	require.NoError(t, f.keeper.LastProcessedBlock.Set(f.ctx, height-1))
	require.ErrorContains(t, submitBlockMsg(f, attestedBlockMsg(t, f, height, block)), "no Bitcoin anchor")
}

// On mainnet (BIP34) the coinbase must encode the block's height, which binds
// the height to the header chain.
func TestSetMsgReportBlock_CoinbaseHeight(t *testing.T) {
	f := initFixture(t)
	block, height := loadMainnetBlock(t, "../../../testdata/block/300003.json")
	// claim the block is one lower than it is
	setBtcAnchor(t, f, height-2, mainnetHeader(t, mainnetHeader300002))
	err := submitBlockMsg(f, attestedBlockMsg(t, f, height-1, block))
	require.ErrorContains(t, err, "coinbase encodes height 300003, not 300002")
}

// At a difficulty period boundary the block's timestamp becomes the period start.
func TestSetMsgReportBlock_PeriodStartAtBoundary(t *testing.T) {
	f := initFixture(t)
	c := newRegtestChain(t, f, 2*2016-1)
	block := c.nextBlock(c.coinbase())
	c.mustSubmit(block)
	start, err := f.keeper.BtcPeriodStartTime.Get(f.ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(block.Header.Timestamp.Unix()), start)

	next := c.nextBlock(c.coinbase())
	c.mustSubmit(next)
	start, err = f.keeper.BtcPeriodStartTime.Get(f.ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(block.Header.Timestamp.Unix()), start, "unchanged inside a period")
}
