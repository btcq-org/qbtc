package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAsset(t *testing.T) {
	asset, err := NewAsset("btcq.btcq")
	assert.Nil(t, err)
	assert.Equal(t, "BTCQ.BTCQ", asset.String())
	assert.True(t, asset.Chain.Equals(BTCQChain))
	assert.True(t, asset.Symbol.Equals(Symbol("BTCQ")))
	assert.True(t, asset.Ticker.Equals(Ticker("BTCQ")))
	assert.False(t, asset.Secured)

	asset, err = NewAsset("btc.btc")
	assert.Nil(t, err)
	assert.Equal(t, "BTC.BTC", asset.String())
	assert.True(t, asset.Chain.Equals(BTCChain))
	assert.True(t, asset.Symbol.Equals(Symbol("BTC")))
	assert.True(t, asset.Ticker.Equals(Ticker("BTC")))
	assert.False(t, asset.Secured)

	asset, err = NewAsset("btcq-btc")
	assert.Nil(t, err)
	assert.Equal(t, "BTCQ-BTC", asset.String())
	assert.True(t, asset.Chain.Equals(BTCQChain))
	assert.True(t, asset.Symbol.Equals(Symbol("BTC")))
	assert.True(t, asset.Ticker.Equals(Ticker("BTC")))
	assert.True(t, asset.Secured)
}
