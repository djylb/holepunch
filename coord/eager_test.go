package coord

import (
	"net/netip"
	"testing"

	"github.com/djylb/holepunch/coord/internal/simclient"
	"github.com/djylb/holepunch/internal/testkit"
	"github.com/djylb/holepunch/protocol"
)

// TestEagerGo: a round 1 that neither side prepares for starts right after
// the summaries. The readies that come later still bring their late port
// mappings, queued for the next go, and a second one is ignored.
func TestEagerGo(t *testing.T) {
	r := newRig(t)
	p := r.pair(SessionOptions{})
	sums := p.summaries()
	for i := range 2 {
		if g := expect[protocol.PunchGo](t, p.cl[i]); g.Round != 1 {
			t.Fatalf("go %+v", g)
		}
	}
	if ev := r.waitEvents(EvGo, 1)[0]; !ev.Data.(GoData).Eager {
		t.Fatalf("go event %+v", ev.Data)
	}
	ready := simclient.Ready(sums[0], protocol.RoleInitiator, 1)
	ready.Families[0].PortMap = &protocol.PortMapReport{Method: protocol.PortMapUPnP,
		External: netip.AddrPortFrom(pubI.Addr(), 41000), Internal: localI, LeaseSeconds: 60}
	send(t, p.cl[0], &ready)
	send(t, p.cl[0], &ready)
	testkit.WaitFor(t, "late mapping queued", func() bool {
		p.s.mu.Lock()
		defer p.s.mu.Unlock()
		return len(p.s.st.rounds.portmap[1]) == 1
	})
	p.s.mu.Lock()
	state := p.s.st.state
	p.s.mu.Unlock()
	if state != StatePunching {
		t.Fatalf("state %s", state)
	}
	p.s.Abort(protocol.ReasonCanceled, "")
	r.wait(p.s)
}

// TestEagerGoWaitsForPortMap: a side with port mapping enabled whose report
// carried no mapping may still report one in punch_ready, so round 1 waits
// for the readies.
func TestEagerGoWaitsForPortMap(t *testing.T) {
	r := newRig(t)
	p := r.pair(SessionOptions{})
	rep := simclient.Report(*p.starts[0], 5, "quic", fam(0, simclient.OpenTraits))
	rep.Caps.PortMap = []protocol.PortMapMethod{protocol.PortMapUPnP}
	send(t, p.cl[0], rep)
	p.report(1)
	var sums [2]*protocol.ProbeSummary
	for i := range 2 {
		sums[i] = expect[protocol.ProbeSummary](t, p.cl[i])
	}
	p.s.mu.Lock()
	state := p.s.st.state
	p.s.mu.Unlock()
	if state != StateSummarized {
		t.Fatalf("state %s before the readies", state)
	}
	for i := range 2 {
		send(t, p.cl[i], simclient.Ready(sums[i], roleOf(i), 1))
	}
	for i := range 2 {
		expect[protocol.PunchGo](t, p.cl[i])
	}
	if ev := r.waitEvents(EvGo, 1)[0]; ev.Data.(GoData).Eager {
		t.Fatal("eager go")
	}
	p.s.Abort(protocol.ReasonCanceled, "")
	r.wait(p.s)
}
