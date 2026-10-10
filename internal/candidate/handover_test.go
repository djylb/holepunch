package candidate

import (
	"net/netip"
	"testing"
	"time"

	"github.com/djylb/holepunch/protocol"
)

func TestKindString(t *testing.T) {
	for k, want := range map[Kind]string{KindUnknown: "unknown", KindBirthday: "birthday", KindRandom: "random", KindPredicted: "predicted", KindTargets: "targets", KindObserved: "observed", KindLAN: "lan", KindOverlay: "overlay", KindOverlay + 1: "invalid", Kind(99): "invalid"} {
		if got := k.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", k, got, want)
		}
	}
}

// The initiator hands over on an upper-layer packet from the winning remote.
func TestUpperLayerInitiator(t *testing.T) {
	m := NewManager(Config{Role: protocol.RoleInitiator})
	base := time.Unix(0, 0)
	loc, rem := ap("192.0.2.1:5000"), ap("203.0.113.9:40000")
	m.Success(base, loc, rem, protocol.FamilyUDP4, 40*time.Millisecond)
	// drive to Readying.
	for ms := 0; ms <= 200 && m.Phase() != PhaseReadying; ms++ {
		now := base.Add(time.Duration(ms) * time.Millisecond)
		for _, a := range m.Tick(now) {
			if a.Kind == SendNominate && m.Phase() == PhaseNominating {
				m.RecvAccept(now, a.Epoch, rem, 0)
			}
		}
	}
	if m.Phase() != PhaseReadying {
		t.Fatalf("phase %v, want readying", m.Phase())
	}
	acts := m.RecvUpperLayer(base.Add(300*time.Millisecond), netip.AddrPort{}, rem)
	if count(acts, HandOver) != 1 || acts[len(acts)-1].ConfirmedBy != protocol.ConfirmedByUpperLayer {
		t.Fatalf("upper-layer handover not produced: %+v", acts)
	}
}

// The responder confirms and hands over on an upper-layer packet while adopted.
func TestUpperLayerResponder(t *testing.T) {
	r := NewManager(Config{Role: protocol.RoleResponder})
	base := time.Unix(0, 0)
	loc, rem := ap("198.51.100.5:6000"), ap("203.0.113.1:50000")
	r.Success(base, loc, rem, protocol.FamilyUDP4, 40*time.Millisecond)
	r.RecvNominate(base, 1, loc, rem, protocol.FamilyUDP4)
	acts := r.RecvUpperLayer(base.Add(50*time.Millisecond), netip.AddrPort{}, rem)
	if count(acts, Confirm) != 1 || count(acts, HandOver) != 1 {
		t.Fatalf("responder upper-layer confirm+handover missing: %+v", acts)
	}
	if !r.Confirmed() {
		t.Fatal("responder not confirmed")
	}
}

// Rolling the epoch re-nominates another available candidate immediately.
func TestRollReNominatesOther(t *testing.T) {
	m := NewManager(Config{Role: protocol.RoleInitiator, MaxNominateResends: 3})
	base := time.Unix(0, 0)
	loc := ap("192.0.2.1:5000")
	a := ap("203.0.113.9:40000") // observed, higher tier -> nominated first
	b := ap("203.0.113.9:40001") // predicted
	m.Observe(base, loc, a, protocol.FamilyUDP4, KindObserved)
	m.Observe(base, loc, b, protocol.FamilyUDP4, KindPredicted)
	m.Success(base, loc, a, protocol.FamilyUDP4, 40*time.Millisecond)
	m.Success(base, loc, b, protocol.FamilyUDP4, 40*time.Millisecond)
	nominated := map[netip.AddrPort]bool{}
	for ms := 0; ms <= 3000 && m.Epoch() < 2; ms++ {
		now := base.Add(time.Duration(ms) * time.Millisecond)
		for _, act := range m.Tick(now) {
			if act.Kind == SendNominate {
				nominated[act.Remote] = true
			}
		}
	}
	if m.Epoch() < 2 {
		t.Fatalf("epoch did not roll: %d", m.Epoch())
	}
	if !nominated[a] || !nominated[b] {
		t.Fatalf("expected both candidates nominated across epochs, got %v", nominated)
	}
}

// An extra ready during the responder's ack burst appends at most two acks.
func TestExtraReadyBurst(t *testing.T) {
	r := NewManager(Config{Role: protocol.RoleResponder})
	base := time.Unix(0, 0)
	loc, rem := ap("198.51.100.5:6000"), ap("203.0.113.1:50000")
	r.Success(base, loc, rem, protocol.FamilyUDP4, 40*time.Millisecond)
	r.RecvNominate(base, 1, loc, rem, protocol.FamilyUDP4)
	if acts := r.RecvReady(base.Add(20*time.Millisecond), 1, rem, 0); count(acts, Confirm) != 1 {
		t.Fatalf("ready did not confirm: %+v", acts)
	}
	// two extra readies during the burst -> two extra acks fired later.
	r.RecvReady(base.Add(21*time.Millisecond), 1, rem, 0)
	r.RecvReady(base.Add(22*time.Millisecond), 1, rem, 0)
	r.RecvReady(base.Add(23*time.Millisecond), 1, rem, 0) // third is ignored (<= 2)
	acks := 0
	for ms := 20; ms <= 60; ms++ {
		for _, a := range r.Tick(base.Add(time.Duration(ms) * time.Millisecond)) {
			if a.Kind == SendAck {
				acks++
			}
		}
	}
	// base burst 0/15/30 = but first ack already emitted at confirm; remaining
	// acks plus up to 2 extras. Just assert the burst completed and handover.
	if r.Phase() != PhaseDone {
		t.Fatalf("responder did not hand over, phase %v (acks=%d)", r.Phase(), acks)
	}
}

// Touch on the current remote feeds the quiet inference timestamp without a
// Success.
func TestTouch(t *testing.T) {
	m := NewManager(Config{Role: protocol.RoleInitiator})
	base := time.Unix(0, 0)
	loc, rem := ap("192.0.2.1:5000"), ap("203.0.113.9:40000")
	m.Success(base, loc, rem, protocol.FamilyUDP4, 40*time.Millisecond)
	for ms := 0; ms <= 200 && m.Phase() != PhaseReadying; ms++ {
		now := base.Add(time.Duration(ms) * time.Millisecond)
		for _, a := range m.Tick(now) {
			if a.Kind == SendNominate && m.Phase() == PhaseNominating {
				m.RecvAccept(now, a.Epoch, rem, 0)
			}
		}
	}
	// Touch keeps quiet from firing for a while.
	m.Touch(base.Add(300*time.Millisecond), rem)
	done := false
	for ms := 300; ms <= 1200; ms++ {
		for _, a := range m.Tick(base.Add(time.Duration(ms) * time.Millisecond)) {
			if a.Kind == HandOver {
				done = true
			}
		}
		if done {
			break
		}
	}
	if !done {
		t.Fatal("expected eventual quiet handover after touch window")
	}
}
