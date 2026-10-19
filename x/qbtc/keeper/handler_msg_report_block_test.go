package keeper_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"cosmossdk.io/collections"
	sdkmath "cosmossdk.io/math"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// Real mainnet blocks, rebuilt from their getblock JSON and checked against the
// real header of the previous block.
func TestSetMsgReportBlock_MainnetBlocks(t *testing.T) {
	setUtxo := func(t *testing.T, f *fixture, txid string, vout uint32, amount, entitled uint64) {
		utxo := types.UTXO{
			Txid:           txid,
			Vout:           vout,
			Amount:         amount,
			EntitledAmount: entitled,
			ScriptPubKey: &types.ScriptPubKeyResult{
				Hex:     "76a91488ac",
				Type:    "pubkeyhash",
				Address: "1J6QsrCXRTZusGEeyg44BcoqgM4SZXTXhC",
			},
		}
		require.NoError(t, f.keeper.Utxoes.Set(f.ctx, utxo.GetKey(), utxo))
	}
	inputs := []struct {
		name       string
		fileName   string
		prevHeader string
		setup      func(st *testing.T, f *fixture)
		checkFunc  func(st *testing.T, f *fixture)
	}{
		{
			name:       "block 923828",
			fileName:   "../../../testdata/block/923828.json",
			prevHeader: mainnetHeader923827,
			setup: func(st *testing.T, f *fixture) {
				setUtxo(st, f, "714e0124f36a99799ab034629d1a3abe248dc492b7f1404467d50921d617d6f8", 279, 2748504, 2748504)
				setUtxo(st, f, "da31e2e6b9b8fd8c34d944d79ccf92d69bfb28823c6ec36a9118d7280cd4d315", 0, 5433643000, 5433643000)
			},
			checkFunc: func(st *testing.T, f *fixture) {
				_, err := f.keeper.Utxoes.Get(f.ctx, "8eb9d5922df115ccea20adf84f2b1e6664fd9a2c196a3f863303283353d52a33-0")
				require.Error(st, err)
				// the coinbase output has the block's fee (65602 sats) deducted
				require.Equal(st, uint64(313461906), getTestEntitlement(st, f, "7025015c9a362d21ac2731bcad2f0ef6c7bb9a1a7bf297c443eb53e952beb8dd", 1))
			},
		},
		{
			name:       "block 300003",
			fileName:   "../../../testdata/block/300003.json",
			prevHeader: mainnetHeader300002,
			checkFunc: func(st *testing.T, f *fixture) {
				// no inputs are preloaded, so every input counts as already spent
				require.Equal(st, uint64(2502676489), getTestEntitlement(st, f, "effbacb359a68252c25d349cea55eaff68ef549aef6aef0faa30e38ab48080a3", 0))
				require.Equal(st, uint64(0), getTestEntitlement(st, f, "e8bd07a2b2a68965ef732d6dad74d3af16ac384aff1c92a42e1707f5bc8fb714", 0))
			},
		},
		{
			name:       "block 300003 with preload utxos",
			fileName:   "../../../testdata/block/300003.json",
			prevHeader: mainnetHeader300002,
			setup: func(st *testing.T, f *fixture) {
				setUtxo(st, f, "c99a1454100bc1a57ff5206dcfcaf196907f5724417d9e0a496741949fe0d20d", 963, 53048210, 53048210)
			},
			checkFunc: func(st *testing.T, f *fixture) {
				require.Equal(st, uint64(2502666489), getTestEntitlement(st, f, "effbacb359a68252c25d349cea55eaff68ef549aef6aef0faa30e38ab48080a3", 0))
				require.Equal(st, uint64(20000000), getTestEntitlement(st, f, "2bda3732778da19cbf8799aceed3a6ab270948aeac85678bee013ddf3070687e", 0))
				require.Equal(st, uint64(33038210), getTestEntitlement(st, f, "2bda3732778da19cbf8799aceed3a6ab270948aeac85678bee013ddf3070687e", 1))
			},
		},
		{
			name:       "block 300003 with partial claimed utxos",
			fileName:   "../../../testdata/block/300003.json",
			prevHeader: mainnetHeader300002,
			setup: func(st *testing.T, f *fixture) {
				setUtxo(st, f, "d510799f177184922edfb98adcc023b1f13d087c2bad700798972f0defcffdca", 1, 9494012, 9494012)
				setUtxo(st, f, "b66a7f1e6e9030cecf87a0d450f257857c34de737934fc013be8ebe76982e20c", 1, 13766651, 13766651)
				setUtxo(st, f, "bc84b6ec6473499eb9c5cbd266cc17dfb177efe2a35c9da843b884106be829aa", 0, 11825990, 0)
			},
			checkFunc: func(st *testing.T, f *fixture) {
				require.Equal(st, uint64(2502666489), getTestEntitlement(st, f, "effbacb359a68252c25d349cea55eaff68ef549aef6aef0faa30e38ab48080a3", 0))
				require.Equal(st, uint64(14659050), getTestEntitlement(st, f, "bfa3ed4869f33192946dcc03d7789d6be32aa07f083e9752fcea2a5568a9ea47", 0))
				require.Equal(st, uint64(8591612), getTestEntitlement(st, f, "bfa3ed4869f33192946dcc03d7789d6be32aa07f083e9752fcea2a5568a9ea47", 1))
			},
		},
	}
	for _, tc := range inputs {
		t.Run(tc.name, func(st *testing.T) {
			f := initFixture(st)
			block, height := loadMainnetBlock(st, tc.fileName)
			setBtcAnchor(st, f, "", height-1, mainnetHeader(st, tc.prevHeader))
			if tc.setup != nil {
				tc.setup(st, f)
			}

			require.NoError(st, submitBlockMsg(f, attestedBlockMsg(st, f, height, block)))
			require.Equal(st, height, getLastProcessed(st, f))
			var tip bytes.Buffer
			require.NoError(st, block.Header.Serialize(&tip))
			stored, err := f.keeper.BtcTipHeader.Get(f.ctx)
			require.NoError(st, err)
			require.Equal(st, tip.Bytes(), stored, "the block becomes the tip")
			tc.checkFunc(st, f)
		})
	}
}

// A self-send with a claim memo claims the outputs to the memo's qbtc address
// in the block that contains it.
func TestSetMsgReportBlock_MemoClaim(t *testing.T) {
	const (
		inputTxid = "dbdd7837a8f7e113f6038b6cf659600538c53b7a742e2b9b1f22de3039e912ba"
		amount    = 88_109_900_000
		fee       = 1_000
	)
	f := initFixture(t)
	minted := sdkmath.ZeroInt()
	f.bankKeeper.EXPECT().MintCoins(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, _ string, coins sdk.Coins) error {
			minted = minted.Add(coins.AmountOf(sdk.DefaultBondDenom))
			return nil
		}).AnyTimes()
	f.bankKeeper.EXPECT().SendCoinsFromModuleToAccount(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	c := newRegtestChain(t, f, 800000)
	setTestUtxo(t, f, c.params, inputTxid, 0, amount, amount)
	memoAddr, err := f.GetRandomQbtcAddress()
	require.NoError(t, err)

	claim := spendTx([]wire.OutPoint{outpoint(t, inputTxid, 0)}, p2pkhOut(t, amount-fee), claimMemoOut(t, memoAddr))
	c.mustSubmit(c.nextBlock(c.coinbase(), claim))

	require.Equal(t, uint64(0), getTestEntitlement(t, f, claim.TxHash().String(), 0))
	require.Equal(t, sdkmath.NewInt(amount-fee).String(), minted.String())
}

// A claimed UTXO spent together with a small unclaimed one gives a partially entitled output.
// Spending that output again must not reset its entitlement to its full value.
func TestSetMsgReportBlock_PartialEntitlementIsNotReset(t *testing.T) {
	const (
		claimedTxid = "1111111111111111111111111111111111111111111111111111111111111111"
		dustTxid    = "2222222222222222222222222222222222222222222222222222222222222222"
		claimedSats = 10 * btcutil.SatoshiPerBitcoin
		dustSats    = 10_000
		fee         = 2_000
	)
	// tx A spends the claimed UTXO plus the dust; its output is entitled to the dust minus the fee
	txA := spendTx([]wire.OutPoint{outpoint(t, claimedTxid, 0), outpoint(t, dustTxid, 0)}, p2pkhOut(t, claimedSats+dustSats-fee))
	// tx B spends that output alone
	txB := spendTx([]wire.OutPoint{outpoint(t, txA.TxHash().String(), 0)}, p2pkhOut(t, claimedSats+dustSats-2*fee))

	for _, sameBlock := range []bool{true, false} {
		t.Run(fmt.Sprintf("same block %v", sameBlock), func(st *testing.T) {
			f := initFixture(st)
			c := newRegtestChain(st, f, 800000)
			setTestUtxo(st, f, c.params, claimedTxid, 0, claimedSats, 0)
			setTestUtxo(st, f, c.params, dustTxid, 0, dustSats, dustSats)

			if sameBlock {
				c.mustSubmit(c.nextBlock(c.coinbase(), txA, txB))
			} else {
				c.mustSubmit(c.nextBlock(c.coinbase(), txA))
				require.Equal(st, uint64(dustSats-fee), getTestEntitlement(st, f, txA.TxHash().String(), 0))
				c.mustSubmit(c.nextBlock(c.coinbase(), txB))
			}
			require.Equal(st, uint64(dustSats-2*fee), getTestEntitlement(st, f, txB.TxHash().String(), 0))
		})
	}
}

// The same loop, but tx B is a memo claim, which mints in the block that contains it.
func TestSetMsgReportBlock_PartialEntitlementMemoClaim(t *testing.T) {
	const (
		claimedTxid = "1111111111111111111111111111111111111111111111111111111111111111"
		dustTxid    = "2222222222222222222222222222222222222222222222222222222222222222"
		claimedSats = 10 * btcutil.SatoshiPerBitcoin
		dustSats    = 10_000
		fee         = 2_000
	)
	f := initFixture(t)
	minted := sdkmath.ZeroInt()
	f.bankKeeper.EXPECT().MintCoins(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, _ string, coins sdk.Coins) error {
			minted = minted.Add(coins.AmountOf(sdk.DefaultBondDenom))
			return nil
		}).AnyTimes()
	f.bankKeeper.EXPECT().SendCoinsFromModuleToAccount(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	c := newRegtestChain(t, f, 800000)
	setTestUtxo(t, f, c.params, claimedTxid, 0, claimedSats, 0)
	setTestUtxo(t, f, c.params, dustTxid, 0, dustSats, dustSats)
	memoAddr, err := f.GetRandomQbtcAddress()
	require.NoError(t, err)

	txA := spendTx([]wire.OutPoint{outpoint(t, claimedTxid, 0), outpoint(t, dustTxid, 0)}, p2pkhOut(t, claimedSats+dustSats-fee))
	txB := spendTx([]wire.OutPoint{outpoint(t, txA.TxHash().String(), 0)}, p2pkhOut(t, claimedSats+dustSats-2*fee), claimMemoOut(t, memoAddr))
	c.mustSubmit(c.nextBlock(c.coinbase(), txA, txB))

	require.Equal(t, sdkmath.NewInt(dustSats-2*fee).String(), minted.String())
	require.Equal(t, uint64(0), getTestEntitlement(t, f, txB.TxHash().String(), 0))
}

// claimable * amount does not fit in uint64 here (5e9 * 5e9 = 2.5e19).
func TestSetMsgReportBlock_EntitlementDoesNotOverflow(t *testing.T) {
	const (
		claimedTxid = "1111111111111111111111111111111111111111111111111111111111111111"
		openTxid    = "2222222222222222222222222222222222222222222222222222222222222222"
		fiftyBTC    = 50 * btcutil.SatoshiPerBitcoin
	)
	f := initFixture(t)
	c := newRegtestChain(t, f, 800000)
	setTestUtxo(t, f, c.params, claimedTxid, 0, fiftyBTC, 0)
	setTestUtxo(t, f, c.params, openTxid, 0, fiftyBTC, fiftyBTC)

	txA := spendTx([]wire.OutPoint{outpoint(t, claimedTxid, 0), outpoint(t, openTxid, 0)}, p2pkhOut(t, fiftyBTC), p2pkhOut(t, fiftyBTC))
	c.mustSubmit(c.nextBlock(c.coinbase(), txA))
	require.Equal(t, uint64(fiftyBTC/2), getTestEntitlement(t, f, txA.TxHash().String(), 0))
	require.Equal(t, uint64(fiftyBTC/2), getTestEntitlement(t, f, txA.TxHash().String(), 1))
}

// When every input is fully entitled, each output keeps its full value.
func TestSetMsgReportBlock_UnclaimedInputsKeepFullEntitlement(t *testing.T) {
	const inTxid = "1111111111111111111111111111111111111111111111111111111111111111"
	f := initFixture(t)
	c := newRegtestChain(t, f, 800000)
	setTestUtxo(t, f, c.params, inTxid, 0, 100_000_003, 100_000_003)
	setTestUtxo(t, f, c.params, inTxid, 1, 7, 7)

	txA := spendTx([]wire.OutPoint{outpoint(t, inTxid, 0), outpoint(t, inTxid, 1)},
		p2pkhOut(t, 33_333_333), p2pkhOut(t, 66_666_667), p2pkhOut(t, 1))
	c.mustSubmit(c.nextBlock(c.coinbase(), txA))
	txid := txA.TxHash().String()
	require.Equal(t, uint64(33_333_333), getTestEntitlement(t, f, txid, 0))
	require.Equal(t, uint64(66_666_667), getTestEntitlement(t, f, txid, 1))
	require.Equal(t, uint64(1), getTestEntitlement(t, f, txid, 2))
}

// An input that is not in the store contributes nothing to the claimable or
// input totals. The outputs share the known claimable total pro rata, so they
// never get more than the known inputs had.
func TestSetMsgReportBlock_MissingInput(t *testing.T) {
	const (
		missingTxid = "1111111111111111111111111111111111111111111111111111111111111111"
		knownTxid   = "2222222222222222222222222222222222222222222222222222222222222222"
	)
	cases := []struct {
		name        string
		outputs     []int64
		entitlement []uint64
	}{
		// known input 100,000 < outputs 150,000: no fee can be computed, so the
		// full known 100,000 is split pro rata
		{"outputs above known inputs", []int64{90_000, 60_000}, []uint64{60_000, 40_000}},
		// known input 100,000 > outputs 80,000: the 20,000 fee comes off the
		// claimable total, and each output gets its full value
		{"outputs below known inputs", []int64{50_000, 30_000}, []uint64{50_000, 30_000}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(st *testing.T) {
			f := initFixture(st)
			c := newRegtestChain(st, f, 800000)
			setTestUtxo(st, f, c.params, knownTxid, 0, 100_000, 100_000)
			outs := make([]*wire.TxOut, len(tc.outputs))
			for i, sats := range tc.outputs {
				outs[i] = p2pkhOut(st, sats)
			}
			txA := spendTx([]wire.OutPoint{outpoint(st, missingTxid, 0), outpoint(st, knownTxid, 0)}, outs...)
			c.mustSubmit(c.nextBlock(c.coinbase(), txA))
			for i, want := range tc.entitlement {
				require.Equal(st, want, getTestEntitlement(st, f, txA.TxHash().String(), uint32(i)))
			}
		})
	}
}

// A UTXO record that cannot be read (here: bytes that do not decode) fails the
// block instead of being skipped as if the input did not exist.
func TestSetMsgReportBlock_UnreadableInputFailsBlock(t *testing.T) {
	const badTxid = "3333333333333333333333333333333333333333333333333333333333333333"
	f := initFixture(t)
	c := newRegtestChain(t, f, 800000)
	badKey := fmt.Sprintf("%s-0", badTxid)
	rawKey, err := collections.EncodeKeyWithPrefix(types.UTXOKeys.Bytes(), collections.StringKey, badKey)
	require.NoError(t, err)
	sdk.UnwrapSDKContext(f.ctx).KVStore(f.storeKey).Set(rawKey, []byte{0xff, 0xff, 0xff})
	_, err = f.keeper.Utxoes.Get(f.ctx, badKey)
	require.Error(t, err)
	require.NotErrorIs(t, err, collections.ErrNotFound)

	txA := spendTx([]wire.OutPoint{outpoint(t, badTxid, 0)}, p2pkhOut(t, 90_000))
	err = c.submit(c.nextBlock(c.coinbase(), txA))
	require.ErrorContains(t, err, "fail to get UTXO")

	require.Equal(t, uint64(800000), getLastProcessed(t, f), "the block must not be applied")
	_, err = f.keeper.Utxoes.Get(f.ctx, fmt.Sprintf("%s-0", txA.TxHash()))
	require.ErrorIs(t, err, collections.ErrNotFound)
}

// Outputs record their script, its class and (for address types) the address
// on the chain's network.
func TestSetMsgReportBlock_RecordsOutputScript(t *testing.T) {
	f := initFixture(t)
	c := newRegtestChain(t, f, 800000)
	coinbase := c.coinbase(5_000_000_000)
	c.mustSubmit(c.nextBlock(coinbase))

	utxo, err := f.keeper.Utxoes.Get(f.ctx, fmt.Sprintf("%s-0", coinbase.TxHash()))
	require.NoError(t, err)
	require.Equal(t, uint64(5_000_000_000), utxo.Amount)
	require.Equal(t, uint64(800001), utxo.BlockHeight)
	require.Equal(t, "pubkeyhash", utxo.ScriptPubKey.Type)
	require.Equal(t, testAddress(t, &chaincfg.RegressionNetParams), utxo.ScriptPubKey.Address)
}
