// Package contracts provides embedded WASM contract bytecode for testing.
package contracts

import (
	_ "embed"
)

// HackatomContract is a simple CosmWasm contract used for testing.
// It has basic functionality: verifier can release funds to beneficiary.
//
//go:embed hackatom.wasm
var hackatomContract []byte

// HackatomContractWasm returns the hackatom contract bytecode.
func HackatomContractWasm() []byte {
	return hackatomContract
}

// HackatomInitMsg is the instantiate message for the hackatom contract.
type HackatomInitMsg struct {
	Verifier    string `json:"verifier"`
	Beneficiary string `json:"beneficiary"`
}

// HackatomQueryMsg is the query message for the hackatom contract.
type HackatomQueryMsg struct {
	// Verifier returns the verifier address
	Verifier *struct{} `json:"verifier,omitempty"`
	// OtherBalance returns the balance of another address
	OtherBalance *OtherBalanceQuery `json:"other_balance,omitempty"`
}

// OtherBalanceQuery is used to query balance of an address.
type OtherBalanceQuery struct {
	Address string `json:"address"`
}

// VerifierResponse is the response from verifier query.
type VerifierResponse struct {
	Verifier string `json:"verifier"`
}

// HackatomExecuteMsg is the execute message for the hackatom contract.
type HackatomExecuteMsg struct {
	// Release sends all funds to beneficiary
	Release *struct{} `json:"release,omitempty"`
}
