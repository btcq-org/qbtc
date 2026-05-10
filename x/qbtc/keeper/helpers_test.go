package keeper_test

// pad32 right-pads b with zeros to make a 32-byte Bitcoin txid suitable for
// the slim UTXO proto. Tests use it to keep readable string-based seeds
// without re-encoding to hex.
func pad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out, b)
	return out
}
