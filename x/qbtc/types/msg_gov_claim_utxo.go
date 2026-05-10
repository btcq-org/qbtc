package types

import (
	"encoding/hex"
	"strconv"

	se "github.com/cosmos/cosmos-sdk/types/errors"
)

func (m *MsgGovClaimUTXO) ValidateBasic() error {
	if m.Authority == "" {
		return se.ErrInvalidRequest.Wrap("authority is required")
	}
	if len(m.Utxos) == 0 {
		return se.ErrInvalidRequest.Wrap("must provide at least one UTXO to claim")
	}
	if len(m.Utxos) > MaxBatchClaimUTXOs {
		return se.ErrInvalidRequest.Wrapf("too many UTXOs in batch: %d (max %d)", len(m.Utxos), MaxBatchClaimUTXOs)
	}
	for _, utxo := range m.Utxos {
		if len(utxo.Txid) != BitcoinTxIDLength {
			return se.ErrInvalidRequest.Wrapf("txid must be %d bytes, got %d", BitcoinTxIDLength, len(utxo.Txid))
		}
	}
	return nil
}

func (m *MsgGovClaimUTXO) GetUtxoString() []string {
	utxoIds := make([]string, len(m.Utxos))
	for i, utxo := range m.Utxos {
		utxoIds[i] = hex.EncodeToString(utxo.Txid) + ":" + strconv.FormatInt(int64(utxo.Vout), 10)
	}
	return utxoIds
}
