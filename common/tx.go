package common

import (
	"fmt"
	"regexp"
	"strings"
)

type (
	// TxID is a string that can uniquely represent a transaction on different
	// block chain
	TxID string
	// TxIDs is a slice of TxID
	TxIDs []TxID
)

var (
	// BlankTxID represent blank
	BlankTxID = TxID("0000000000000000000000000000000000000000000000000000000000000000")

	regexIsCosmosIndexed = regexp.MustCompile(`^[0-9a-fA-F]{64}-[0-9]+$`)
	regexHex64           = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
)

// NewTxID parse the input hash as TxID
func NewTxID(hash string) (TxID, error) {
	// for cosmos tx hash with appended id
	// eg: DDFB48D1A6084FD41FE1D37BB5A950234F4AED3CF8036AED12633389BDC37DB9-1
	if len(hash) > 64 {
		if regexIsCosmosIndexed.MatchString(hash) {
			return TxID(hash), nil
		}
	}

	switch len(hash) {
	case 64:
		if !regexHex64.MatchString(hash) {
			return TxID(""), fmt.Errorf("txid error: must be 64 hex characters")
		}
	default:
		err := fmt.Errorf("txid error: must be 64 characters (got %d)", len(hash))
		return TxID(""), err
	}

	return TxID(strings.ToUpper(hash)), nil
}

// Equals check whether two TxID are the same
func (tx TxID) Equals(tx2 TxID) bool {
	return strings.EqualFold(tx.String(), tx2.String())
}

// IsEmpty return true when the tx represent empty string
func (tx TxID) IsEmpty() bool {
	return strings.TrimSpace(tx.String()) == ""
}

func (tx TxID) IsBlank() bool {
	return tx.Equals(BlankTxID)
}

// String implement fmt.Stringer
func (tx TxID) String() string {
	return string(tx)
}
