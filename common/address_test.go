package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddress(t *testing.T) {
	_, err := NewAddress("1lejrrtta9cgr49fuh7ktu3sddhe0ff7wenlpn6")
	assert.NotNil(t, err)
	_, err = NewAddress("bnb1lejrrtta9cgr49fuh7ktu3sddhe0ff7wenlpn6X")
	assert.NotNil(t, err)
	_, err = NewAddress("bogus")
	assert.NotNil(t, err)
	assert.True(t, Address("").IsEmpty())
	assert.Equal(t, NoAddress, Address(""))

	noop, err := NewAddress("noop")
	assert.Nil(t, err)
	assert.Equal(t, NoopAddress, noop)

	btcqAddr, err := NewAddress("btcq1mw9p5ys9rfrlpcd5et7dqq5r7h4yzl9jw5ghgp")
	assert.Nil(t, err)
	assert.Equal(t, "btcq1mw9p5ys9rfrlpcd5et7dqq5r7h4yzl9jw5ghgp", btcqAddr.String())
	assert.False(t, btcqAddr.IsEmpty())
	accAddr, err := btcqAddr.AccAddress()
	assert.Nil(t, err)
	assert.Equal(t, "btcq1mw9p5ys9rfrlpcd5et7dqq5r7h4yzl9jw5ghgp", accAddr.String())

	addr, err := NewAddress("1MirQ9bwyQcGVJPwKUgapu5ouK2E2Ey4gX")
	assert.Nil(t, err)
	assert.Equal(t, "1MirQ9bwyQcGVJPwKUgapu5ouK2E2Ey4gX", addr.String())
	assert.False(t, addr.IsEmpty())
	_, err = addr.AccAddress()
	assert.NotNil(t, err)
	_, err = NewAddress("3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC")
	assert.Nil(t, err)

	_, err = NewAddress("02192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b4")
	assert.NotNil(t, err)
	_, err = NewAddress("03b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e65")
	assert.NotNil(t, err)

	_, err = NewAddress("06192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b4" +
		"0d45264838c0bd96852662ce6a847b197376830160c6d2eb5e6a4c44d33f453e")
	assert.NotNil(t, err)

	_, err = NewAddress("07b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e65" +
		"37a576782eba668a7ef8bd3b3cfb1edb7117ab65129b8a2e681f3c1e0908ef7b")
	assert.NotNil(t, err)
	addr, err = NewAddress("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4")
	assert.Nil(t, err)
	assert.Equal(t, "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", addr.String())
	assert.False(t, addr.IsEmpty())

	addr, err = NewAddress("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3")
	assert.Nil(t, err)
	assert.Equal(t, "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", addr.String())
	assert.False(t, addr.IsEmpty())
	_, err = addr.AccAddress()
	assert.NotNil(t, err)
	_, err = NewAddress("BC1SW50QA3JX3S")
	assert.NotNil(t, err)
	_, err = NewAddress("bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj")
	assert.NotNil(t, err)
	_, err = NewAddress("bc1pfy63nact82mfmts5jv87p2uayxqs29gf8070td7kzhwzx6zc9ruq9u7xy7")
	assert.Nil(t, err)
}
