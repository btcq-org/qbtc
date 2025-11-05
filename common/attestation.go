package common

import "bytes"

func (a *Attestation) Equals(other *Attestation) bool {
	if a == nil || other == nil {
		return a == other
	}
	return a.Address == other.Address && bytes.Equal(a.Signature, other.Signature)
}

func removeAttestations(
	existing []*Attestation,
	toRemove []*Attestation,
) []*Attestation {
	newAtts := make([]*Attestation, 0)
	for _, att1 := range existing {
		found := false
		for _, att2 := range toRemove {
			if att1.Equals(att2) {
				found = true
			}
		}
		if !found {
			newAtts = append(newAtts, att1)
		}
	}
	return newAtts
}
