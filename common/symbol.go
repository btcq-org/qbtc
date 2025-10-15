package common

import (
	"errors"
	"regexp"
	"strings"
)

var isAlphaNumeric = regexp.MustCompile(`^[A-Za-z0-9-._]+$`).MatchString

// Symbol represent an asset
type Symbol string

// NewSymbol parse the input as symbol
func NewSymbol(input string) (Symbol, error) {
	if !isAlphaNumeric(input) {
		return "", errors.New("invalid symbol")
	}

	return Symbol(strings.ToUpper(input)), nil
}

func (s Symbol) Valid() error {
	if !isAlphaNumeric(s.String()) {
		return errors.New("symbol must be alphanumeric")
	}
	return nil
}

// Ticker return the ticker part of symbol
func (s Symbol) Ticker() (Ticker, error) {
	parts := strings.Split(s.String(), "-")
	return NewTicker(parts[0])
}

// Equals check whether two symbol are the same
func (s Symbol) Equals(s2 Symbol) bool {
	return strings.EqualFold(s.String(), s2.String())
}

// IsEmpty return true when symbol is just empty string
func (s Symbol) IsEmpty() bool {
	return strings.TrimSpace(s.String()) == ""
}

// String implement fmt.Stringer
func (s Symbol) String() string {
	// uppercasing again just in case someone created a ticker via Chain("rune")
	return strings.ToUpper(string(s))
}
