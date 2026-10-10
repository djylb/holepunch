package candidate

import (
	"testing"
	"time"

	"github.com/djylb/holepunch/protocol"
)

func TestTableBestTiering(t *testing.T) {
	tab := newTable()
	t0 := time.Unix(0, 0)
	loc := ap("192.0.2.1:5000")
	obs := ap("203.0.113.9:40000")
	pred := ap("203.0.113.9:40100")
	tab.Observe(t0, loc, obs, protocol.FamilyUDP4, KindObserved)
	tab.Observe(t0, loc, pred, protocol.FamilyUDP4, KindPredicted)

	if b := tab.Best(t0); b != nil {
		t.Fatalf("Best should be nil before any success, got %v", b.Remote)
	}
	tab.Success(t0, loc, pred, protocol.FamilyUDP4, 5*time.Millisecond)
	if b := tab.Best(t0); b == nil || b.Remote != pred {
		t.Fatalf("Best = %v, want predicted", b)
	}
	tab.Success(t0, loc, obs, protocol.FamilyUDP4, 100*time.Millisecond)
	if b := tab.Best(t0); b == nil || b.Remote != obs {
		t.Fatalf("Best = %v, want observed (higher tier)", b)
	}
}

func TestHysteresis(t *testing.T) {
	t0 := time.Unix(0, 0)
	cur := &Candidate{Remote: ap("203.0.113.1:1"), Kind: KindObserved, Reason: "observed", Responsive: true, SucceededAt: t0}
	later := &Candidate{Remote: ap("203.0.113.2:2"), Kind: KindObserved, Reason: "observed", Responsive: true, SucceededAt: t0.Add(time.Second)}
	if betterForNomination(later, cur) {
		t.Fatal("equal-score later candidate should not replace")
	}
	lan := &Candidate{Remote: ap("203.0.113.3:3"), Kind: KindLAN, Reason: "lan", Responsive: true, SucceededAt: t0}
	if !betterForNomination(lan, cur) {
		t.Fatal("higher-tier different-reason candidate should replace")
	}
}

func TestCooldownExcludesFromBest(t *testing.T) {
	tab := newTable()
	t0 := time.Unix(0, 0)
	loc := ap("192.0.2.1:5000")
	r := ap("203.0.113.9:40000")
	tab.Success(t0, loc, r, protocol.FamilyUDP4, 40*time.Millisecond)
	tab.get(loc, r).CooldownUntil = t0.Add(500 * time.Millisecond)
	if b := tab.Best(t0); b != nil {
		t.Fatal("cooled-down candidate must be excluded")
	}
	if b := tab.Best(t0.Add(600 * time.Millisecond)); b == nil {
		t.Fatal("candidate should return after cooldown")
	}
}

func TestCandKindMapping(t *testing.T) {
	cases := []struct {
		kind Kind
		resp bool
		want protocol.CandKind
	}{
		{KindLAN, true, protocol.CandLAN},
		{KindObserved, true, protocol.CandDirect},
		{KindTargets, true, protocol.CandTargets},
		{KindPredicted, true, protocol.CandPredicted},
		{KindRandom, true, protocol.CandRandom},
		{KindBirthday, true, protocol.CandBirthday},
		{KindOverlay, true, protocol.CandOverlay},
		{KindUnknown, true, protocol.CandPeerReflexive},
		{KindUnknown, false, protocol.CandDirect},
	}
	for _, c := range cases {
		cand := &Candidate{Kind: c.kind, Responsive: c.resp}
		if got := cand.CandKind(); got != c.want {
			t.Errorf("kind %v resp %v -> %q, want %q", c.kind, c.resp, got, c.want)
		}
	}
}

// Every kind reports a cand_kind the wire accepts: a peer's port mapping
// ranks as targets or lan, and portmap is no wire value.
func TestCandKindOnWire(t *testing.T) {
	for k := KindUnknown; k <= KindOverlay; k++ {
		for _, resp := range []bool{false, true} {
			c := &Candidate{Kind: k, Responsive: resp}
			rr := protocol.RoundResult{SessionID: "s1", Role: protocol.RoleInitiator, Round: 1, Status: protocol.RoundConfirmed,
				Path: &protocol.PathInfo{Family: protocol.FamilyUDP4, Local: ap("192.0.2.1:5000"), Remote: ap("203.0.113.9:40000"),
					Round: 1, Epoch: 1, CandKind: c.CandKind(), Kind: protocol.PathPublic}}
			if err := rr.Validate(); err != nil {
				t.Errorf("kind %v resp %v: cand_kind %q rejected: %v", k, resp, c.CandKind(), err)
			}
		}
	}
}

// TestBestOverlay checks the overlay rule: an overlay candidate is
// nominated only when no other candidate answered, or when its RTT is at
// most 0.8 × the best other candidate's; it never beats another one on
// score alone, and a candidate without an RTT sample keeps the other path.
func TestBestOverlay(t *testing.T) {
	now := time.Unix(100, 0)
	loc := ap("192.0.2.1:5000")
	ovl, pub := ap("100.101.102.103:5000"), ap("203.0.113.9:40000")
	for _, c := range []struct {
		name         string
		ovlRTT       time.Duration // 0: the overlay candidate did not answer
		pubRTT       time.Duration // 0: the public one did not answer; < 0: answered without a sample
		wantOverlay  bool
		wantNoWinner bool
	}{
		{"overlay alone", 30 * time.Millisecond, 0, true, false},
		{"public alone", 0, 30 * time.Millisecond, false, false},
		{"overlay faster than 0.8", 20 * time.Millisecond, 30 * time.Millisecond, true, false},
		{"overlay at 0.8", 24 * time.Millisecond, 30 * time.Millisecond, true, false},
		{"overlay slightly faster", 25 * time.Millisecond, 30 * time.Millisecond, false, false},
		{"overlay slower", 40 * time.Millisecond, 30 * time.Millisecond, false, false},
		{"public without sample", 5 * time.Millisecond, -1, false, false},
		{"nothing", 0, 0, false, true},
	} {
		tab := newTable()
		tab.Observe(now, loc, ovl, protocol.FamilyUDP4, KindOverlay)
		tab.Observe(now, loc, pub, protocol.FamilyUDP4, KindObserved)
		if c.ovlRTT > 0 {
			tab.Success(now, loc, ovl, protocol.FamilyUDP4, c.ovlRTT)
		}
		switch {
		case c.pubRTT > 0:
			tab.Success(now, loc, pub, protocol.FamilyUDP4, c.pubRTT)
		case c.pubRTT < 0:
			tab.Success(now, loc, pub, protocol.FamilyUDP4, 0)
		}
		got := tab.Best(now)
		switch {
		case c.wantNoWinner:
			if got != nil {
				t.Errorf("%s: got %v", c.name, got.Remote)
			}
		case got == nil:
			t.Errorf("%s: no winner", c.name)
		case (got.Remote == ovl) != c.wantOverlay:
			t.Errorf("%s: winner %v (%v)", c.name, got.Remote, got.Kind)
		}
	}
}
