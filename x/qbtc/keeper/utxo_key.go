package keeper

import "fmt"

// claimPrefix marks an OP_RETURN output as a UTXO claim: "claim:<qbtc-address>".
const claimPrefix = "claim:"

// getUTXOKey returns the key used to store a UTXO in the key value store.
func getUTXOKey(txID string, vOut uint32) string {
	return fmt.Sprintf("%s-%d", txID, vOut)
}
