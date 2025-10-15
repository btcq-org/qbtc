package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAsset(t *testing.T) {
	asset, err := NewAsset("btcq.btcq")
	assert.Nil(t, err)
	assert.Equal(t, "BTCQ.BTCQ", asset.String())
}
