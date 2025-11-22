package bitcoin

import (
	"bufio"
	"bytes"
	"io"
	"testing"

	qbtctypes "github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/cosmos/gogoproto/proto"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestWriteUtxo(t *testing.T) {

	pVout := qbtctypes.UTXO{
		Txid:           "test",
		Vout:           0,
		Amount:         uint64(0.15 * 1e8), // convert to satoshis
		EntitledAmount: uint64(0.15 * 1e8),
		ScriptPubKey: &qbtctypes.ScriptPubKeyResult{
			Hex:     "76a91489abcdefabbaabbaabbaabbaabbaabbaabba88ac",
			Type:    "pubkeyhash",
			Address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
		},
	}
	data, err := proto.Marshal(&pVout)
	assert.NoError(t, err)
	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)
	_, err = writer.Write(protowire.AppendFixed32(nil, uint32(len(data))))
	assert.NoError(t, err)
	_, err = writer.Write(data)
	assert.NoError(t, err)
	writer.Flush()

	reader := bufio.NewReader(&buf)
	sizeBytes := make([]byte, protowire.SizeFixed32())
	n, err := io.ReadFull(reader, sizeBytes)
	assert.NoError(t, err)
	assert.Equal(t, 4, n)
	size, n := protowire.ConsumeFixed32(sizeBytes)
	assert.Equal(t, 4, n)
	assert.Equal(t, uint32(len(data)), size)

	utxoBytes := make([]byte, size)
	n, err = io.ReadFull(reader, utxoBytes)
	assert.NoError(t, err)
	assert.Equal(t, int(size), n)
	var pUtxo qbtctypes.UTXO
	err = proto.Unmarshal(utxoBytes, &pUtxo)
	assert.NoError(t, err)
	assert.Equal(t, pVout, pUtxo)
}
