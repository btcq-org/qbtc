package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTicker(t *testing.T) {
	btcqTicker, err := NewTicker("btcq")
	assert.Nil(t, err)
	assert.False(t, btcqTicker.IsEmpty())
	assert.Equal(t, "BTCQ", btcqTicker.String())
	assert.Equal(t, BTCQTicker, btcqTicker)

	_, err = NewTicker("")
	assert.NotNil(t, err) // empty

	_, err = NewTicker("too long of a ticker")
	assert.NotNil(t, err)

}
