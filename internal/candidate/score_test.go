package candidate

import (
	"testing"
	"time"

	"github.com/djylb/holepunch/protocol"
)

// baseScore and Score cover every tier, and the responsive boost dominates.
func TestScoreTiers(t *testing.T) {
	order := []Kind{KindBirthday, KindRandom, KindPredicted, KindTargets, KindObserved, KindLAN}
	prev := 0
	for _, k := range order {
		s := (&Candidate{Kind: k}).Score()
		if s <= prev {
			t.Errorf("kind %v score %d not above previous %d", k, s, prev)
		}
		prev = s
	}
	if (&Candidate{Kind: KindUnknown}).Score() != scoreNone {
		t.Error("unknown kind should score scoreNone")
	}
	resp := (&Candidate{Kind: KindRandom, Responsive: true}).Score()
	if resp <= (&Candidate{Kind: KindLAN}).Score() {
		t.Error("responsive random must outrank non-responsive LAN")
	}
}

// betterForNomination tie-breaks by NomFailures, the success time and
// FirstSeen once scores and success counts match; a nil candidate never wins.
func TestBetterTieBreak(t *testing.T) {
	t0 := time.Unix(0, 0)
	base := func() *Candidate {
		return &Candidate{Remote: ap("203.0.113.1:1"), Kind: KindObserved, Reason: "observed", Responsive: true, SucceededAt: t0, FirstSeen: t0}
	}
	cur := base()
	cur.NomFailures = 2
	chal := base()
	chal.Remote = ap("203.0.113.2:2")
	chal.NomFailures = 0
	if !betterForNomination(chal, cur) {
		t.Error("fewer nomination failures should win")
	}
	cur2 := base()
	later := base()
	later.Remote = ap("203.0.113.3:3")
	later.FirstSeen = t0.Add(time.Second)
	if betterForNomination(later, cur2) {
		t.Error("later FirstSeen should not win a tie")
	}
	unsucceeded := base()
	unsucceeded.Remote = ap("203.0.113.4:4")
	unsucceeded.SucceededAt = time.Time{}
	if betterForNomination(unsucceeded, cur2) || !betterForNomination(cur2, unsucceeded) {
		t.Error("a candidate with a success time should beat one without")
	}
	if betterForNomination(nil, cur2) {
		t.Error("a nil candidate should never win")
	}
}

func TestTableLen(t *testing.T) {
	tab := newTable()
	t0 := time.Unix(0, 0)
	tab.Observe(t0, ap("192.0.2.1:1"), ap("203.0.113.1:1"), protocol.FamilyUDP4, KindObserved)
	tab.Observe(t0, ap("192.0.2.1:1"), ap("203.0.113.2:2"), protocol.FamilyUDP4, KindPredicted)
	if tab.Len() != 2 {
		t.Fatalf("Len = %d, want 2", tab.Len())
	}
}

// Winner is empty until confirmed.
func TestWinnerBeforeConfirm(t *testing.T) {
	m := NewManager(Config{Role: protocol.RoleInitiator})
	if _, ok := m.Winner(); ok {
		t.Fatal("Winner should be empty before confirm")
	}
}

// A repeated accept in the Readying phase re-sends ready (rate-limited).
func TestRepeatedAcceptResendsReady(t *testing.T) {
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
	if m.Phase() != PhaseReadying {
		t.Fatalf("phase %v, want readying", m.Phase())
	}
	// a repeated accept >= 20 ms after the last ready re-sends ready.
	acts := m.RecvAccept(base.Add(500*time.Millisecond), m.Epoch(), rem, 0)
	if count(acts, SendReady) != 1 {
		t.Fatalf("repeated accept did not re-send ready: %+v", acts)
	}
	// a wrong-epoch / wrong-remote accept is ignored.
	if a := m.RecvAccept(base.Add(600*time.Millisecond), m.Epoch(), ap("203.0.113.9:9999"), 0); a != nil {
		t.Fatalf("accept from wrong remote acted: %+v", a)
	}
}

// startNominating with no responsive candidate falls back to punching.
func TestCollectWithNoBest(t *testing.T) {
	m := NewManager(Config{Role: protocol.RoleInitiator})
	base := time.Unix(0, 0)
	loc, rem := ap("192.0.2.1:5000"), ap("203.0.113.9:40000")
	m.Success(base, loc, rem, protocol.FamilyUDP4, 40*time.Millisecond)
	// Put the only candidate into cooldown before the collect timer fires.
	m.Table().get(loc, rem).CooldownUntil = base.Add(10 * time.Second)
	acts := m.Tick(base.Add(200 * time.Millisecond)) // collect fires at ~100ms
	if count(acts, SendNominate) != 0 {
		t.Fatalf("nominated a cooling-down candidate: %+v", acts)
	}
	if m.Phase() != PhasePunching {
		t.Fatalf("phase %v, want back to punching", m.Phase())
	}
}
