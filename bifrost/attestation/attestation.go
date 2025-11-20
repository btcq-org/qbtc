package attestation

import (
	"github.com/libp2p/go-libp2p/core/host"
)

type AttestationGossip struct {
	host host.Host
}

func NewAttestationGossip(host host.Host) *AttestationGossip {
	return &AttestationGossip{
		host: host,
	}
}
