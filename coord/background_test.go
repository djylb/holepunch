package coord

import (
	"testing"

	"github.com/djylb/holepunch/protocol"
)

// The Background session mode.

// TestBackgroundOffer: a Background offer reaches both punch_starts, with
// the slow birthday's sockets and targets in the session budget and a 60 s
// handshake; an explicit policy and explicit timeouts stand; an unknown
// mode is refused.
func TestBackgroundOffer(t *testing.T) {
	r := newRig(t)
	s := r.session(SessionOptions{Mode: protocol.ModeBackground})
	for i := range 2 {
		st := s.Start(roleOf(i))
		b := st.Policy.Budget
		if st.Mode != protocol.ModeBackground || b.MaxSockets != 128 || b.MaxDistinctTargets != 2048 || st.Timeouts.HandshakeTimeoutMs != 60000 {
			t.Fatalf("start %d: mode %q, budget %+v, handshake %d", i, st.Mode, b, st.Timeouts.HandshakeTimeoutMs)
		}
	}
	to := protocol.DefaultTimeouts()
	s = r.session(SessionOptions{Mode: protocol.ModeBackground, Timeouts: &to,
		Policy: &protocol.Policy{Budget: protocol.Budget{MaxSockets: 16}}})
	if st := s.Start(protocol.RoleInitiator); st.Policy.Budget.MaxSockets != 16 || st.Timeouts.HandshakeTimeoutMs != to.HandshakeTimeoutMs ||
		st.Policy.Budget.MaxDistinctTargets != 2048 {
		t.Fatalf("explicit policy and timeouts: %+v %+v", st.Policy.Budget, st.Timeouts)
	}
	if st := r.session(SessionOptions{}).Start(protocol.RoleInitiator); st.Mode != "" || st.Policy.Budget.MaxSockets != protocol.DefaultBudget().MaxSockets {
		t.Fatalf("interactive start: %q %+v", st.Mode, st.Policy.Budget)
	}
	if _, err := r.c.NewSession(SessionOptions{Mode: "lazy"}); !invalidArgument(err) {
		t.Fatalf("unknown mode: %v", err)
	}
}

// TestSessionMode: background needs the offer and both clients.
func TestSessionMode(t *testing.T) {
	bg := protocol.ModeBackground
	rep := func(a, b protocol.SessionMode) [2]protocol.ProbeReport {
		return [2]protocol.ProbeReport{{Mode: a}, {Mode: b}}
	}
	for _, c := range []struct {
		offer protocol.SessionMode
		r     [2]protocol.ProbeReport
		want  protocol.SessionMode
	}{
		{bg, rep(bg, bg), bg},
		{bg, rep(bg, ""), ""},
		{bg, rep(protocol.ModeInteractive, bg), ""},
		{"", rep(bg, bg), ""},
	} {
		if got := sessionMode(c.offer, c.r); got != c.want {
			t.Errorf("offer %q reports %q/%q: %q, want %q", c.offer, c.r[0].Mode, c.r[1].Mode, got, c.want)
		}
	}
}

// TestBackgroundClassGuard: the background class runs only in a Background
// session of a pair with a random side, from any round; otherwise it is
// held to heavy, and heavy's own rule applies.
func TestBackgroundClassGuard(t *testing.T) {
	_, s := testSession(t)
	s.mu.Lock()
	defer s.mu.Unlock()
	st := &s.st
	st.lastGranted, st.pairRND = protocol.BudgetBalanced, true
	if got := s.guardClassLocked(2, protocol.BudgetBackground, 0); got != protocol.BudgetHeavy {
		t.Fatalf("interactive session: %s", got)
	}
	st.mode = protocol.ModeBackground
	if got := s.guardClassLocked(2, protocol.BudgetBackground, 0); got != protocol.BudgetBackground {
		t.Fatalf("background session, round 2: %s", got)
	}
	st.lastGranted = ""
	if got := s.guardClassLocked(1, protocol.BudgetBackground, 0); got != protocol.BudgetBackground {
		t.Fatalf("round 1, the memory's choice: %s", got)
	}
	st.pairRND, st.lastGranted = false, protocol.BudgetBalanced
	if got := s.guardClassLocked(2, protocol.BudgetBackground, 0); got != protocol.BudgetBalanced {
		t.Fatalf("no random side: %s", got)
	}
}
