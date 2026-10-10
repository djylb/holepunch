package holepunch

import (
	"sync"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

// TestRefreshAnchor: a refresh the server asks for before the summary
// sends two probes, refreshGap apart, from two new sockets — two new
// mappings of a symmetric NAT — marked with the refresh phases, which
// natprobe hands to the coordinator; the sockets are closed as soon as
// their probe left.
func TestRefreshAnchor(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	seq := w.n.NAT(nattest.SymmetricSeq(1))
	so := newSoloOn(t, w, seq.Host(), nil)
	var mu sync.Mutex
	var got []nat.SandwichEvent
	nat.AttachSandwichSink(so.s.h, func(ev nat.SandwichEvent) {
		mu.Lock()
		got = append(got, ev)
		mu.Unlock()
	})
	so.startWith(testTimeouts(), nil)
	so.report()
	open := so.host.OpenSockets()
	so.link.send(protocol.Assist{SessionID: so.s.sid, From: protocol.RoleServer, Kind: protocol.AssistRefresh, Round: 1, Family: protocol.FamilyUDP4})
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	evs := append([]nat.SandwichEvent(nil), got...)
	mu.Unlock()
	if len(evs) != 2 || evs[0].Phase != nat.RefreshFirst || evs[1].Phase != nat.RefreshSecond || evs[0].Round != 1 {
		t.Fatalf("refresh events %+v", evs)
	}
	if evs[0].Observed.Addr() != evs[1].Observed.Addr() || evs[1].Observed.Port() != evs[0].Observed.Port()+1 {
		t.Fatalf("two new mappings of a sequential NAT: %v then %v", evs[0].Observed, evs[1].Observed)
	}
	if gap := evs[1].At.Sub(evs[0].At); gap < refreshGap/2 {
		t.Fatalf("probes %v apart, want about %v", gap, refreshGap)
	}
	for i := 0; so.host.OpenSockets() != open && i < 100; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if n := so.host.OpenSockets(); n != open {
		t.Fatalf("%d sockets open after the refresh, %d before", n, open)
	}
	so.cancel()
	so.result(10 * time.Second)
}
