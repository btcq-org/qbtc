package ebifrost

import (
	"testing"

	common "github.com/btcq-org/qbtc/common"
	"github.com/cometbft/cometbft/crypto"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	"github.com/stretchr/testify/require"
)

// TestSignerAddress test to generate the signer address for the ebifrost signer
func TestSignerAddress(t *testing.T) {
	t.Skip("skipping signer address test")
	signerAddress, err := bech32.ConvertAndEncode(common.AccountAddressPrefix, crypto.AddressHash([]byte("ebifrost_signer")))
	if err != nil {
		t.Fatalf("failed to encode signer address: %v", err)
	}

	require.Equal(t, "qbtc102aqxl4u8h9q4lcsruq56kkmeey0v699phhvuv", signerAddress)
}
