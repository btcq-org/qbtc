package common

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/assert"
)

func TestChain(t *testing.T) {
	btcChain, err := NewChain("BTC")
	assert.Nil(t, err)
	assert.Equal(t, BTCChain, btcChain)
	assert.False(t, btcChain.IsEmpty())
	assert.Equal(t, "BTC", btcChain.String())

	_, err = NewChain("B") // too short
	assert.NotNil(t, err)

	chains := Chains{"DOGE", "DOGE", "BTC"}
	assert.True(t, chains.Has(BTCChain))
	assert.False(t, chains.Has(Chain("ETH")))
	assert.True(t, chains.Has(Chain("DOGE")))
	uniq := chains.Distinct()
	assert.Len(t, uniq, 2)

	btcQChain, err := NewChain("BTCQ")
	assert.Nil(t, err)
	assert.Equal(t, BTCQChain, btcQChain)
	assert.NotEqual(t, BTCChain, btcQChain)

	assert.Equal(t, BTCChain.GetGasAsset(), BTCAsset)
	assert.Equal(t, BTCQChain.GetGasAsset(), BTCQAsset)
	assert.Equal(t, EmptyChain.GetGasAsset(), EmptyAsset)

	assert.Equal(t, BTCChain.AddressPrefix(MockNet), chaincfg.RegressionNetParams.Bech32HRPSegwit)
	assert.Equal(t, BTCChain.AddressPrefix(MainNet), chaincfg.MainNetParams.Bech32HRPSegwit)
	assert.Equal(t, BTCChain.AddressPrefix(StageNet), chaincfg.MainNetParams.Bech32HRPSegwit)

}
