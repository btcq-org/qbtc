package zk

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadOrDownloadHermezSRS_RequiresPinnedHash(t *testing.T) {
	_, _, err := LoadOrDownloadHermezSRS(t.TempDir(), 20, 1)
	require.ErrorContains(t, err, "no pinned Blake2b hash")
}

// A PTAU file already in the cache is hash-checked too, not only a fresh download.
func TestLoadOrDownloadHermezSRS_ChecksCachedPTAU(t *testing.T) {
	dir := t.TempDir()
	raw := filepath.Join(dir, fmt.Sprintf("powersOfTau28_hez_final_%02d.ptau", DefaultPtauPower))
	require.NoError(t, os.WriteFile(raw, []byte("not a ptau file"), 0o600))

	_, _, err := LoadOrDownloadHermezSRS(dir, DefaultPtauPower, 1)
	require.ErrorContains(t, err, "PTAU hash verification failed")
	require.NoFileExists(t, raw)
}
