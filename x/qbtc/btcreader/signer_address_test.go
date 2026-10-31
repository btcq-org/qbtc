package btcreader_test

import (
	"testing"

	common "github.com/btcq-org/qbtc/common"
	"github.com/cometbft/cometbft/crypto"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	"github.com/stretchr/testify/require"
)

// TestSignerAddress test to generate the signer address for the injected MsgBtcBlock
func TestSignerAddress(t *testing.T) {
	t.Skip("skipping signer address test")
	signerAddress, err := bech32.ConvertAndEncode(common.AccountAddressPrefix, crypto.AddressHash([]byte("btc_block_signer")))
	if err != nil {
		t.Fatalf("failed to encode signer address: %v", err)
	}

	require.Equal(t, "qbtc1z4zgnyehf8dk0fgrwrx9mrt8qk8qlxhvaat6u4", signerAddress)
}
