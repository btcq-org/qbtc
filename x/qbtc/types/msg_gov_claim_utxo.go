package types

import (
	se "github.com/cosmos/cosmos-sdk/types/errors"
)

func (m *MsgGovClaimUTXO) ValidateBasic() error {
	if m.Authority == "" {
		return se.ErrInvalidRequest.Wrap("authority is required")
	}
	if len(m.Utxos) == 0 {
		return se.ErrInvalidRequest.Wrap("must provide at least one UTXO to claim")
	}
	for _, utxo := range m.Utxos {
		if utxo.Txid == "" {
			return se.ErrInvalidRequest.Wrap("txid is required")
		}
	}
	return nil
}

func (m *MsgGovClaimUTXO) GetUtxos() []string {
	utxoIds := make([]string, len(m.Utxos))
	for i, utxo := range m.Utxos {
		utxoIds[i] = utxo.Txid + ":" + string(rune(utxo.Vout))
	}
	return utxoIds
}
