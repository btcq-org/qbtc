package keeper_test

import (
	"bytes"
	"testing"

	"cosmossdk.io/math"

	"github.com/btcq-org/qbtc/x/secured/keeper"
	"github.com/btcq-org/qbtc/x/secured/types"
)

// TestCanonicalObservationsDigestOrderIndependent ensures that two validators
// who submit the same observations in different orders compute the same
// digest. Without this property, signatures cannot be cross-verified.
func TestCanonicalObservationsDigestOrderIndependent(t *testing.T) {
	a := types.ObservedTxIn{
		Txid: "aaaa", Vout: 0, BtcSender: "bc1q-a", BtcRecipient: "bc1q-vault",
		AmountSats: math.NewUint(100), Memo: "+:1", BtcBlockHeight: 800_000,
	}
	b := types.ObservedTxIn{
		Txid: "bbbb", Vout: 1, BtcSender: "bc1q-b", BtcRecipient: "bc1q-vault",
		AmountSats: math.NewUint(200), Memo: "=:qbtc:cosmos1xxx:50", BtcBlockHeight: 800_001,
	}
	c := types.ObservedTxIn{
		Txid: "cccc", Vout: 0, BtcSender: "bc1q-c", BtcRecipient: "bc1q-vault",
		AmountSats: math.NewUint(300), Memo: "", BtcBlockHeight: 800_002,
	}

	d1 := keeper.CanonicalObservationsDigest([]types.ObservedTxIn{a, b, c})
	d2 := keeper.CanonicalObservationsDigest([]types.ObservedTxIn{c, a, b})
	d3 := keeper.CanonicalObservationsDigest([]types.ObservedTxIn{b, c, a})
	if !bytes.Equal(d1, d2) || !bytes.Equal(d1, d3) {
		t.Fatalf("digest not order-independent: %x %x %x", d1, d2, d3)
	}
}

// TestCanonicalObservationsDigestDistinguishesContent: changing a single
// field changes the digest.
func TestCanonicalObservationsDigestDistinguishesContent(t *testing.T) {
	base := types.ObservedTxIn{
		Txid: "aaaa", Vout: 0, BtcSender: "bc1q-a", BtcRecipient: "bc1q-vault",
		AmountSats: math.NewUint(100), Memo: "+:1", BtcBlockHeight: 800_000,
	}
	cases := []func(types.ObservedTxIn) types.ObservedTxIn{
		func(o types.ObservedTxIn) types.ObservedTxIn { o.Txid = "aaab"; return o },
		func(o types.ObservedTxIn) types.ObservedTxIn { o.Vout = 1; return o },
		func(o types.ObservedTxIn) types.ObservedTxIn { o.AmountSats = math.NewUint(101); return o },
		func(o types.ObservedTxIn) types.ObservedTxIn { o.Memo = "+:2"; return o },
		func(o types.ObservedTxIn) types.ObservedTxIn { o.BtcRecipient = "bc1q-other"; return o },
		func(o types.ObservedTxIn) types.ObservedTxIn { o.BtcBlockHeight = 800_001; return o },
	}
	d0 := keeper.CanonicalObservationsDigest([]types.ObservedTxIn{base})
	for i, mutate := range cases {
		got := keeper.CanonicalObservationsDigest([]types.ObservedTxIn{mutate(base)})
		if bytes.Equal(d0, got) {
			t.Fatalf("case %d: mutation did not change digest", i)
		}
	}
}

func TestCanonicalOutboundDigestStable(t *testing.T) {
	d1 := keeper.CanonicalOutboundDigest(42, "abc123", 800_000)
	d2 := keeper.CanonicalOutboundDigest(42, "abc123", 800_000)
	if !bytes.Equal(d1, d2) {
		t.Fatalf("stable digest mismatch")
	}
	d3 := keeper.CanonicalOutboundDigest(42, "abc124", 800_000)
	if bytes.Equal(d1, d3) {
		t.Fatalf("digest collides on different broadcast txid")
	}
}
