package holepunch

import (
	"context"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/protocol"
)

// Every round's sandwich helper is a new socket — a new internal
// endpoint, so that both of its probes map anew on any NAT — which holds a
// place in the socket budget until the round releases it; release closes
// it and ends its read loop.
func TestSandwichHelperPerRound(t *testing.T) {
	_, h := simHost(t)
	rt := newTestRuntime(t, fakeClock(t), h)
	ctx := context.Background()
	primary, err := rt.socks.open(ctx, protocol.FamilyUDP4, netipAP("0.0.0.0", 0), PurposeProbe, nat.IndexPrimary, primaryRecvBuffer)
	if err != nil {
		t.Fatal(err)
	}
	rt.socks.setLimit(2)
	a := rt.socks.sandwichHelper(ctx, primary)
	if a == nil || a.id != nat.SocketID(protocol.FamilyUDP4, nat.IndexSandwich) || a.local.Addr() != primary.local.Addr() {
		t.Fatalf("helper %+v", a)
	}
	if b := rt.socks.sandwichHelper(ctx, primary); b != nil {
		t.Fatal("a second helper past the socket budget")
	}
	rt.socks.release(a)
	select {
	case <-a.readDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the released helper's read loop still runs")
	}
	b := rt.socks.sandwichHelper(ctx, primary)
	if b == nil || b.local == a.local {
		t.Fatalf("next round's helper %+v, the last one %+v", b, a)
	}
	if rt.socks.byAddr(a.local) != nil || rt.socks.byAddr(b.local) != b {
		t.Fatal("the pool still holds the released helper")
	}
	rt.socks.release(b)
}
