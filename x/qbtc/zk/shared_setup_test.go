//go:build testing

package zk

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	testSetupOnce   sync.Once
	testSetupResult *SetupResult
	testSetupErr    error
)

// sharedTestSetup runs the PLONK setup once for the package and returns the
// same result to every caller: the setup is deterministic and takes minutes.
func sharedTestSetup(t *testing.T) *SetupResult {
	t.Helper()
	testSetupOnce.Do(func() {
		testSetupResult, testSetupErr = SetupWithOptions(TestSetupOptions())
	})
	require.NoError(t, testSetupErr, "PLONK setup should succeed")
	return testSetupResult
}
