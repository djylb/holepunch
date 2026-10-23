package holepunch

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/internal/testkit"
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
	so.s.h.AttachSandwichSink(func(ev nat.SandwichEvent) {
		mu.Lock()
		got = append(got, ev)
		mu.Unlock()
	})
	so.startWith(testTimeouts(), nil)
	so.report()
	open := so.host.OpenSockets()
	so.link.send(protocol.Assist{SessionID: so.s.sid, From: protocol.RoleServer, Kind: protocol.AssistRefresh, Round: 1, Family: protocol.FamilyUDP4})
	testkit.WaitFor(t, "two refresh events", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got) >= 2
	})
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
	testkit.WaitFor(t, fmt.Sprintf("the %d sockets open before the refresh", open), func() bool { return so.host.OpenSockets() == open })
	so.cancel()
	so.result(10 * time.Second)
}
