package common

import (
	"testing"

	"cosmossdk.io/math"
	"github.com/stretchr/testify/assert"
)

func TestCoin(t *testing.T) {
	btcAsset, err := NewAsset("BTC.BTC")
	assert.Nil(t, err)
	coin := NewCoin(btcAsset, math.NewUint(100000000))
	assert.Equal(t, "100000000 BTC.BTC", coin.String())
	assert.Equal(t, "BTC.BTC", coin.Asset.String())
	assert.Equal(t, math.NewUint(100000000), coin.Amount)

	coin2, err := ParseCoin("100000000 BTC.BTC")
	assert.Nil(t, err)
	assert.Equal(t, coin, coin2)

	_, err = ParseCoin("invalidcoinstring")
	assert.NotNil(t, err)

	_, err = ParseCoin("notanumber BTC.BTC")
	assert.NotNil(t, err)

	c, err := ParseCoin("100000000 BTCQ")
	assert.Nil(t, err)
	assert.Equal(t, c.IsBTCQ(), true)
	assert.Equal(t, c.IsNative(), true)

	c = NewCoin(btcAsset, math.NewUint(0))
	assert.Nil(t, err)
	assert.Equal(t, c.IsEmpty(), true)
}
func TestCoins(t *testing.T) {
	btcAsset, err := NewAsset("BTC.BTC")
	assert.Nil(t, err)
	btcqAsset, err1 := NewAsset("BTCQ.BTCQ")
	assert.Nil(t, err1)
	coins := Coins{
		NewCoin(btcqAsset, math.NewUint(1000)),
		NewCoin(btcAsset, math.NewUint(1000)),
		NewCoin(btcAsset, math.NewUint(1000)),
		NewCoin(btcAsset, math.NewUint(1000)),
	}
	newCoins := coins.Distinct()
	assert.Equal(t, 2, len(newCoins))

	bnbAsset, err := NewAsset("BNB.BNB")
	assert.Nil(t, err)
	oldCoins := Coins{
		NewCoin(bnbAsset, math.NewUint(1000)),
		NewCoin(BTCAsset, math.NewUint(1000)),
	}
	newCoins = oldCoins.Add(NewCoins(
		NewCoin(btcqAsset, math.NewUint(1000)),
		NewCoin(BTCAsset, math.NewUint(1000)),
	)...)
	assert.Equal(t, 3, len(newCoins))
	assert.Equal(t, 2, len(oldCoins))
	// oldCoins asset types are unchanged, while newCoins has all types.

	assert.Equal(t, uint64(1000), newCoins.GetCoin(bnbAsset).Amount.Uint64())
	assert.Equal(t, uint64(2000), newCoins.GetCoin(BTCAsset).Amount.Uint64())
	assert.Equal(t, uint64(1000), newCoins.GetCoin(btcqAsset).Amount.Uint64())
	// For newCoins, the amount adding works as expected.

}
