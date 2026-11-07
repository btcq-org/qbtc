package zk

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckBitcoinAddressCanonical(t *testing.T) {
	const p2wpkh = "bc1q4wr4k0uwzryx9jyss3tsd60gaulpxaggzm3mnc"
	const p2pkh = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

	require.NoError(t, CheckBitcoinAddressCanonical(p2wpkh))
	require.NoError(t, CheckBitcoinAddressCanonical(p2pkh))

	err := CheckBitcoinAddressCanonical(strings.ToUpper(p2wpkh))
	require.Error(t, err, "uppercase bech32 decodes but is not what the chain stores")
	require.Contains(t, err.Error(), p2wpkh)

	require.Error(t, CheckBitcoinAddressCanonical("bc1qnotanaddress"))
	require.Error(t, CheckBitcoinAddressCanonical(""))
}
