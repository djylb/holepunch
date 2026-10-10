package candidate

import (
	"net/netip"
	"testing"
	"time"

	"github.com/djylb/holepunch/protocol"
)

func count(acts []Action, k ActionKind) int {
	n := 0
	for _, a := range acts {
		if a.Kind == k {
			n++
		}
	}
	return n
}

// handshake wires an initiator and a responder over a lossless, zero-latency
// channel and runs them on a fake clock until both hand over.
type handshake struct {
	t                        *testing.T
	init, resp               *Manager
	iLoc, rAddr, rLoc, iAddr netip.AddrPort
	fam                      protocol.Family

	initConfirm, respConfirm bool
	initDone, respDone       bool
	initBy, respBy           protocol.HandoverEvidence
}

func newHandshake(t *testing.T) *handshake {
	return &handshake{
		t:     t,
		init:  NewManager(Config{Role: protocol.RoleInitiator}),
		resp:  NewManager(Config{Role: protocol.RoleResponder}),
		iLoc:  ap("192.0.2.1:5000"),
		rAddr: ap("203.0.113.9:40000"),
		rLoc:  ap("198.51.100.5:6000"),
		iAddr: ap("203.0.113.1:50000"),
		fam:   protocol.FamilyUDP4,
	}
}

func (h *handshake) process(fromInit bool, acts []Action, now time.Time, depth int) {
	if depth > 64 {
		h.t.Fatal("delivery recursion too deep")
	}
	for _, a := range acts {
		switch a.Kind {
		case Confirm:
			if fromInit {
				h.initConfirm = true
			} else {
				h.respConfirm = true
			}
		case HandOver:
			if fromInit {
				h.initDone, h.initBy = true, a.ConfirmedBy
			} else {
				h.respDone, h.respBy = true, a.ConfirmedBy
			}
		case SendNominate:
			if fromInit {
				h.process(false, h.resp.RecvNominate(now, a.Epoch, h.rLoc, h.iAddr, h.fam), now, depth+1)
			}
		case SendReady:
			if fromInit {
				h.process(false, h.resp.RecvReady(now, a.Epoch, h.iAddr, 0), now, depth+1)
			}
		case SendAccept:
			if !fromInit {
				h.process(true, h.init.RecvAccept(now, a.Epoch, h.rAddr, 0), now, depth+1)
			}
		case SendAck:
			if !fromInit {
				h.process(true, h.init.RecvHandoverAck(now, a.Epoch, h.rAddr), now, depth+1)
			}
		case Fail:
			// Nothing to deliver.
		}
	}
}

func (h *handshake) run(maxMs int) time.Time {
	base := time.Unix(100, 0)
	h.init.Success(base, h.iLoc, h.rAddr, h.fam, 40*time.Millisecond)
	h.resp.Success(base, h.rLoc, h.iAddr, h.fam, 40*time.Millisecond)
	for ms := 0; ms <= maxMs; ms++ {
		now := base.Add(time.Duration(ms) * time.Millisecond)
		h.process(true, h.init.Tick(now), now, 0)
		h.process(false, h.resp.Tick(now), now, 0)
		if h.initDone && h.respDone {
			return now
		}
	}
	return base.Add(time.Duration(maxMs) * time.Millisecond)
}

func TestHandshakeHappyPath(t *testing.T) {
	h := newHandshake(t)
	end := h.run(2000)
	if !h.initDone || !h.respDone {
		t.Fatalf("not both handed over: init=%v resp=%v", h.initDone, h.respDone)
	}
	if !h.initConfirm || !h.respConfirm {
		t.Fatalf("not both confirmed: init=%v resp=%v", h.initConfirm, h.respConfirm)
	}
	if h.initBy != protocol.ConfirmedByAck {
		t.Fatalf("initiator confirmed_by = %q, want ack", h.initBy)
	}
	if h.respBy != protocol.ConfirmedByReady {
		t.Fatalf("responder confirmed_by = %q, want ready", h.respBy)
	}
	if h.init.Epoch() != 1 || h.resp.Epoch() != 1 {
		t.Fatalf("epoch init=%d resp=%d, want 1", h.init.Epoch(), h.resp.Epoch())
	}
	w, ok := h.init.Winner()
	if !ok || w.Remote != h.rAddr {
		t.Fatalf("initiator winner = %v ok=%v", w.Remote, ok)
	}
	if end.Sub(time.Unix(100, 0)) > 500*time.Millisecond {
		t.Fatalf("handshake took %v", end.Sub(time.Unix(100, 0)))
	}
}

// Five nominate transmissions at epoch 1 (x2 first burst + 3 resends)
// before the epoch rolls.
func TestNominateResendsBeforeRoll(t *testing.T) {
	m := NewManager(Config{Role: protocol.RoleInitiator})
	base := time.Unix(100, 0)
	loc := ap("192.0.2.1:5000")
	a, b := ap("203.0.113.9:40000"), ap("203.0.113.9:40001")
	m.Success(base, loc, a, protocol.FamilyUDP4, 40*time.Millisecond)
	m.Success(base, loc, b, protocol.FamilyUDP4, 40*time.Millisecond)
	sent := map[uint16]int{}
	for ms := 0; ms <= 2000; ms++ {
		now := base.Add(time.Duration(ms) * time.Millisecond)
		for _, act := range m.Tick(now) {
			if act.Kind == SendNominate {
				sent[act.Epoch]++
			}
		}
		if m.Epoch() >= 2 {
			break
		}
	}
	if sent[1] != 5 {
		t.Errorf("epoch 1 sent %d nominates before rolling; want x2 first + 3 resends = 5", sent[1])
	}
}

// With no UDP RTT sample, rto is clamp(2*100, 150) = 150 ms, so the
// first nominate resend is at 100 (collect) + 150 = 250 ms.
func TestRTONoSample(t *testing.T) {
	m := NewManager(Config{Role: protocol.RoleInitiator})
	base := time.Unix(100, 0)
	loc, rem := ap("192.0.2.1:5000"), ap("203.0.113.9:40000")
	m.Success(base, loc, rem, protocol.FamilyUDP4, 0) // no sample
	var nomTimes []time.Duration
	for ms := 0; ms <= 400; ms++ {
		now := base.Add(time.Duration(ms) * time.Millisecond)
		for _, a := range m.Tick(now) {
			if a.Kind == SendNominate {
				nomTimes = append(nomTimes, now.Sub(base))
			}
		}
	}
	// collect at 100, x2 at 100/110, first resend at 100+150 = 250.
	if len(nomTimes) < 3 || nomTimes[2] != 250*time.Millisecond {
		t.Errorf("nominate times %v; first resend must be 250 ms (rto 150 with no sample)", nomTimes)
	}
}

// The rto uses the winning pair's own RTT, not the session-wide minimum.
func TestRTOFromWinningPair(t *testing.T) {
	m := NewManager(Config{Role: protocol.RoleInitiator})
	base := time.Unix(100, 0)
	loc := ap("192.0.2.1:5000")
	pred := ap("203.0.113.9:40001") // predicted, 5 ms
	obs := ap("203.0.113.9:40000")  // observed (winner), 100 ms
	m.Observe(base, loc, pred, protocol.FamilyUDP4, KindPredicted)
	m.Observe(base, loc, obs, protocol.FamilyUDP4, KindObserved)
	m.Success(base, loc, pred, protocol.FamilyUDP4, 5*time.Millisecond)
	m.Success(base, loc, obs, protocol.FamilyUDP4, 100*time.Millisecond)
	var first, resend time.Duration
	for ms := 0; ms <= 600; ms++ {
		now := base.Add(time.Duration(ms) * time.Millisecond)
		for _, a := range m.Tick(now) {
			if a.Kind == SendNominate && a.Epoch == 1 {
				if a.Remote != obs {
					t.Fatalf("nominated %v, want the observed pair", a.Remote)
				}
				switch {
				case first == 0:
					first = now.Sub(base)
				case now.Sub(base)-first > 20*time.Millisecond && resend == 0:
					resend = now.Sub(base) - first
				}
			}
		}
	}
	if resend != 150*time.Millisecond {
		t.Errorf("winner rtt 100 ms -> rto 150 ms; resend gap %v", resend)
	}
}

// The responder never adopts a lower epoch for the same pair; a stale
// nominate(1) after adopting epoch 2 does not downgrade, and ready(2) confirms.
func TestResponderNoEpochDowngrade(t *testing.T) {
	r := NewManager(Config{Role: protocol.RoleResponder})
	base := time.Unix(100, 0)
	loc, rem := ap("198.51.100.5:6000"), ap("203.0.113.1:50000")
	r.Success(base, loc, rem, protocol.FamilyUDP4, 40*time.Millisecond)
	r.RecvNominate(base, 2, loc, rem, protocol.FamilyUDP4)
	if r.Epoch() != 2 {
		t.Fatalf("adopted epoch %d, want 2", r.Epoch())
	}
	r.RecvNominate(base.Add(5*time.Millisecond), 1, loc, rem, protocol.FamilyUDP4) // stale
	if r.Epoch() != 2 {
		t.Fatalf("epoch downgraded to %d by a stale nominate(1)", r.Epoch())
	}
	got := r.RecvReady(base.Add(20*time.Millisecond), 2, rem, 0)
	if count(got, Confirm) == 0 {
		t.Errorf("ready(2) did not confirm after a stale nominate(1)")
	}
}

func TestEpochRollNoAccept(t *testing.T) {
	m := NewManager(Config{Role: protocol.RoleInitiator, MaxNominateResends: 3})
	base := time.Unix(0, 0)
	loc, rem := ap("192.0.2.1:5000"), ap("203.0.113.9:40000")
	m.Success(base, loc, rem, protocol.FamilyUDP4, 40*time.Millisecond)
	for ms := 0; ms <= 2000; ms++ {
		if m.Epoch() >= 2 {
			break
		}
		m.Tick(base.Add(time.Duration(ms) * time.Millisecond))
	}
	if m.Epoch() < 2 {
		t.Fatalf("epoch did not roll: %d", m.Epoch())
	}
	if c := m.Table().get(loc, rem); c == nil || c.NomFailures == 0 {
		t.Fatal("rolled candidate should record a nomination failure")
	}
}

func TestQuietHandover(t *testing.T) {
	m := NewManager(Config{Role: protocol.RoleInitiator})
	base := time.Unix(0, 0)
	loc, rem := ap("192.0.2.1:5000"), ap("203.0.113.9:40000")
	m.Success(base, loc, rem, protocol.FamilyUDP4, 40*time.Millisecond)
	done := false
	var by protocol.HandoverEvidence
	for ms := 0; ms <= 1500; ms++ {
		now := base.Add(time.Duration(ms) * time.Millisecond)
		for _, a := range m.Tick(now) {
			if a.Kind == SendNominate && m.Phase() == PhaseNominating {
				m.RecvAccept(now, a.Epoch, rem, 0)
			}
			if a.Kind == HandOver {
				done, by = true, a.ConfirmedBy
			}
		}
		if done {
			break
		}
	}
	if !done || by != protocol.ConfirmedByQuiet {
		t.Fatalf("expected quiet handover, done=%v by=%q phase=%v", done, by, m.Phase())
	}
}

func TestHandoverTimeout(t *testing.T) {
	m := NewManager(Config{Role: protocol.RoleInitiator, HandoverTimeout: 300 * time.Millisecond})
	base := time.Unix(0, 0)
	loc, rem := ap("192.0.2.1:5000"), ap("203.0.113.9:40000")
	m.Success(base, loc, rem, protocol.FamilyUDP4, 40*time.Millisecond)
	failed := false
	for ms := 0; ms <= 1000; ms++ {
		now := base.Add(time.Duration(ms) * time.Millisecond)
		for _, a := range m.Tick(now) {
			if a.Kind == SendNominate && m.Phase() == PhaseNominating {
				m.RecvAccept(now, a.Epoch, rem, 0)
			}
			if a.Kind == Fail {
				failed = true
			}
		}
		m.Touch(now, rem) // keep the remote "alive" so quiet never triggers
		if failed {
			break
		}
	}
	if !failed {
		t.Fatalf("expected handover_timeout, phase=%v", m.Phase())
	}
}
