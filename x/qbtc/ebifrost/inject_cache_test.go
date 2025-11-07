package ebifrost_test

import (
	"testing"

	common "github.com/btcq-org/qbtc/common"
	"github.com/btcq-org/qbtc/x/qbtc/ebifrost"
	"github.com/stretchr/testify/require"
)

// TestItem is a simple test type that implements the pattern expected by AddItem
type TestItem struct {
	ID           string
	Attestations []*common.Attestation
}

// TestMergeWithExistingDropsMergedAttestations demonstrates the bug where
// merged attestations are not persisted back into the cache.
func TestMergeWithExistingDropsMergedAttestations(t *testing.T) {
	cache := ebifrost.NewInjectCache[TestItem]()

	// Create initial item with one attestation
	initialItem := TestItem{
		ID: "block-1",
		Attestations: []*common.Attestation{
			{
				Address:   "addr1",
				Signature: []byte("sig1"),
			},
		},
	}

	// Add the initial item to the cache
	cache.Add(initialItem)

	// Create a new item with the same ID but different attestations
	newItem := TestItem{
		ID: "block-1",
		Attestations: []*common.Attestation{
			{
				Address:   "addr2",
				Signature: []byte("sig2"),
			},
		},
	}

	// Try to merge using AddItem
	err := cache.AddItem(
		newItem,
		func(item TestItem) []*common.Attestation {
			return item.Attestations
		},
		func(item TestItem, atts []*common.Attestation) TestItem {
			return TestItem{
				ID:           item.ID,
				Attestations: atts,
			}
		},
		func(a, b TestItem) bool {
			return a.ID == b.ID
		},
	)
	require.NoError(t, err)

	// Retrieve items from cache
	items := cache.Get()
	require.Len(t, items, 1, "Should have exactly one item in cache")

	// BUG: The merged attestations are NOT persisted!
	// The cache still contains only the original attestation
	// Expected: 2 attestations (addr1+sig1 and addr2+sig2)
	// Actual: 1 attestation (only addr1+sig1)
	retrievedItem := items[0]
	require.Equal(t, "block-1", retrievedItem.ID, "Item ID should match")

	// This assertion will FAIL, demonstrating the bug
	// The merged attestation (addr2+sig2) is missing
	if len(retrievedItem.Attestations) != 2 {
		t.Errorf(
			"BUG DEMONSTRATED: Expected 2 attestations after merge, but got %d. "+
				"The merged attestation was not persisted back into the cache. "+
				"Attestations: %v",
			len(retrievedItem.Attestations),
			retrievedItem.Attestations,
		)
	}

	// Verify both attestations are present
	attMap := make(map[string]*common.Attestation)
	for _, att := range retrievedItem.Attestations {
		attMap[att.Address] = att
	}

	require.Contains(t, attMap, "addr1", "Original attestation should be present")
	require.Contains(t, attMap, "addr2", "Merged attestation should be present")
}

// TestMergeWithExistingDirectCall demonstrates the bug when calling MergeWithExisting directly
func TestMergeWithExistingDirectCall(t *testing.T) {
	cache := ebifrost.NewInjectCache[TestItem]()

	// Create initial item
	initialItem := TestItem{
		ID: "block-1",
		Attestations: []*common.Attestation{
			{Address: "addr1", Signature: []byte("sig1")},
		},
	}

	cache.Add(initialItem)

	// Create new item with additional attestation
	newItem := TestItem{
		ID: "block-1",
		Attestations: []*common.Attestation{
			{Address: "addr2", Signature: []byte("sig2")},
		},
	}

	// Call MergeWithExisting directly
	merged := cache.MergeWithExisting(
		newItem,
		func(a, b TestItem) bool {
			return a.ID == b.ID
		},
		func(existing TestItem, new TestItem) {
			// Merge attestations
			existingAtts := existing.Attestations
			for _, newAtt := range new.Attestations {
				attExists := false
				for _, existingAtt := range existingAtts {
					if newAtt.Equals(existingAtt) {
						attExists = true
						break
					}
				}
				if !attExists {
					existingAtts = append(existingAtts, newAtt)
				}
			}
			// Create merged item - but this return value is discarded!
			mergedItem := TestItem{
				ID:           existing.ID,
				Attestations: existingAtts,
			}
			_ = mergedItem // BUG: This merged item is never stored back!
		},
	)

	require.True(t, merged, "Merge should have found existing item")

	// Retrieve from cache
	items := cache.Get()
	require.Len(t, items, 1)

	retrievedItem := items[0]

	// BUG: The merged attestations are NOT persisted!
	// The merge function creates a merged item but MergeWithExisting doesn't store it
	if len(retrievedItem.Attestations) != 2 {
		t.Errorf(
			"BUG DEMONSTRATED: Expected 2 attestations after merge, but got %d. "+
				"The merge function created a merged item but it was never stored back. "+
				"Attestations: %v",
			len(retrievedItem.Attestations),
			retrievedItem.Attestations,
		)
	}
}
