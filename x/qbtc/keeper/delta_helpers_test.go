package keeper

import (
	"testing"

	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

func TestDeriveScriptInfo(t *testing.T) {
	hash20 := make([]byte, 20)
	for i := range hash20 {
		hash20[i] = byte(i + 1)
	}
	hash32 := make([]byte, 32)
	for i := range hash32 {
		hash32[i] = byte(i + 1)
	}

	p2pkhAddr, err := btcutil.NewAddressPubKeyHash(hash20, chainParams)
	require.NoError(t, err)
	p2pkh, err := txscript.PayToAddrScript(p2pkhAddr)
	require.NoError(t, err)

	p2wpkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(hash20, chainParams)
	require.NoError(t, err)
	p2wpkh, err := txscript.PayToAddrScript(p2wpkhAddr)
	require.NoError(t, err)

	p2shAddr, err := btcutil.NewAddressScriptHashFromHash(hash20, chainParams)
	require.NoError(t, err)
	p2sh, err := txscript.PayToAddrScript(p2shAddr)
	require.NoError(t, err)

	p2trAddr, err := btcutil.NewAddressTaproot(hash32, chainParams)
	require.NoError(t, err)
	p2tr, err := txscript.PayToAddrScript(p2trAddr)
	require.NoError(t, err)

	cases := []struct {
		name     string
		script   []byte
		wantType string
		wantAddr string
	}{
		{"p2pkh", p2pkh, "pubkeyhash", p2pkhAddr.EncodeAddress()},
		{"p2wpkh", p2wpkh, "witness_v0_keyhash", p2wpkhAddr.EncodeAddress()},
		{"p2sh", p2sh, "scripthash", p2shAddr.EncodeAddress()},
		{"p2tr", p2tr, "witness_v1_taproot", p2trAddr.EncodeAddress()},
		{"nonstandard", []byte{0x6a, 0x00}, "nulldata", ""},
		{"empty", nil, "nonstandard", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotType, gotAddr := deriveScriptInfo(tc.script)
			require.Equal(t, tc.wantType, gotType)
			require.Equal(t, tc.wantAddr, gotAddr)
		})
	}
}

func TestGetDeltaClaimMemo(t *testing.T) {
	memoScript := func(memo string) []byte {
		s, err := txscript.NullDataScript([]byte(memo))
		require.NoError(t, err)
		return s
	}

	t.Run("valid claim memo", func(t *testing.T) {
		out := []*types.BtcTxOut{
			{Value: 1000, ScriptPubKey: []byte{0x00, 0x14}},
			{Value: 0, ScriptPubKey: memoScript("claim:qbtc1abc")},
		}
		require.Equal(t, "qbtc1abc", getDeltaClaimMemo(out))
	})

	t.Run("no op_return", func(t *testing.T) {
		out := []*types.BtcTxOut{{Value: 1000, ScriptPubKey: []byte{0x00, 0x14}}}
		require.Equal(t, "", getDeltaClaimMemo(out))
	})

	t.Run("op_return without claim prefix", func(t *testing.T) {
		out := []*types.BtcTxOut{{Value: 0, ScriptPubKey: memoScript("hello world")}}
		require.Equal(t, "", getDeltaClaimMemo(out))
	})
}

func TestBtcBlockDeltaDigestDeterministic(t *testing.T) {
	mk := func() *types.BtcBlockDelta {
		return &types.BtcBlockDelta{
			Height:    100,
			BlockHash: []byte{1, 2, 3},
			Txs: []*types.BtcTx{{
				Txid:    []byte{9, 9},
				Outputs: []*types.BtcTxOut{{Value: 5, ScriptPubKey: []byte{0x6a}}},
			}},
		}
	}
	require.Equal(t, mk().Digest(), mk().Digest())
	require.Len(t, mk().Digest(), 32)

	other := mk()
	other.Height = 101
	require.NotEqual(t, mk().Digest(), other.Digest())
}
