package types

import "strconv"

// GetKey returns the unique key for the BlockGossip message, which is its hash.
func (m *BlockGossip) GetKey() string {
	return m.GetHash() + "-" + strconv.Itoa(int(m.GetHeight()))
}
