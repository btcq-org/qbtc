package app

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// A zero-height export is refused before it reads any state: qbtc does not
// reset the distribution, staking and slashing heights it would need.
func TestExportForZeroHeightRefused(t *testing.T) {
	_, err := (&App{}).ExportAppStateAndValidators(true, nil, nil)
	require.ErrorContains(t, err, "--for-zero-height is not supported")
}
