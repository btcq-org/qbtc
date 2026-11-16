//go:build testing

package main

import (
	"sync"
	"testing"

	"github.com/btcq-org/qbtc/x/qbtc/zk"
	"github.com/stretchr/testify/require"
)

var (
	zkSetupOnce   sync.Once
	zkSetupResult *zk.SetupResult
	zkSetupErr    error
)

// sharedZKSetup runs the PLONK setup once for the package and returns the same
// result to every caller: the setup is deterministic and takes minutes.
func sharedZKSetup(t *testing.T) *zk.SetupResult {
	t.Helper()
	zkSetupOnce.Do(func() {
		zkSetupResult, zkSetupErr = zk.SetupWithOptions(zk.TestSetupOptions())
	})
	require.NoError(t, zkSetupErr, "PLONK setup should succeed")
	return zkSetupResult
}
