package plan

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	api "github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

// The anchor refresh before a round.

func refreshOf(fam protocol.Family, ip netip.Addr, first, second uint16, at, gap time.Duration) api.AnchorRefresh {
	return api.AnchorRefresh{Family: fam, First: netip.AddrPortFrom(ip, first), Second: netip.AddrPortFrom(ip, second), FirstAt: at, SecondAt: at + gap}
}

func TestRefreshRate(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.3")
	r := refreshOf(protocol.FamilyUDP4, ip, 40000, 40003, time.Second, 100*time.Millisecond)
	if l, ok := anchorRate(r, 1); !ok || l < 19.9 || l > 20.1 {
		t.Fatalf("rate %v %v, want 20/s", l, ok)
	}
	if d := refreshDrift(20, r, r.SecondAt+400*time.Millisecond); d != 8-driftMargin {
		t.Fatalf("drift %d, want %d", d, 8-driftMargin)
	}
	quiet := refreshOf(protocol.FamilyUDP4, ip, 40000, 40001, time.Second, 100*time.Millisecond)
	if l, ok := anchorRate(quiet, 1); !ok || l != 0 || refreshDrift(l, quiet, 5*time.Second) != 0 {
		t.Fatalf("quiet NAT: rate %v", l)
	}
	down := refreshOf(protocol.FamilyUDP4, ip, 1025, 65534, time.Second, 100*time.Millisecond)
	if l, ok := anchorRate(down, -1); !ok || l < 19.9 || l > 20.1 {
		t.Fatalf("downward across the wrap: rate %v %v", l, ok)
	}
	for _, bad := range []api.AnchorRefresh{
		refreshOf(protocol.FamilyUDP4, ip, 40003, 40000, time.Second, 100*time.Millisecond), // backwards
		refreshOf(protocol.FamilyUDP4, ip, 40000, 40003, time.Second, time.Millisecond),     // too close to tell
	} {
		if _, ok := anchorRate(bad, 1); ok {
			t.Errorf("refresh %+v measured a rate", bad)
		}
	}
}

// The probe's anchor stretches the baseline over the whole time since
// probing: from it to the refresh's newest mapping, the side's own
// mappings are every earlier round's and the refresh's own before that
// mapping. Counts the NAT does not match, or an anchor on another IP,
// leave the two probes' own rate.
func TestRefreshRateBaseline(t *testing.T) {
	f := protocol.FamilyUDP4
	ip := netip.MustParseAddr("203.0.113.3")
	tr := protocol.Traits{Family: f, Observed: netip.AddrPortFrom(ip, 39990), PortAnchor: 39990, PortAnchorMs: 500}
	// 39990 at 0.5 s, 40000 at 0.9 s, 40003 at 1.0 s: 13 steps in 0.5 s.
	r := refreshOf(f, ip, 40000, 40003, 900*time.Millisecond, 100*time.Millisecond)
	mapped := func(n int) []api.RoundOutcome {
		return []api.RoundOutcome{{Round: 1, Families: []api.FamilyRound{{Family: f, Mapped: [2]int{n, 0}}}}}
	}
	onlyFirst, onlySecond := r, r
	onlyFirst.Second, onlySecond.First = netip.AddrPort{}, netip.AddrPort{}
	other := tr
	other.Observed = netip.AddrPortFrom(netip.MustParseAddr("203.0.113.4"), 39990)
	for _, c := range []struct {
		name string
		in   api.RoundInput
		r    api.AnchorRefresh
		tr   protocol.Traits
		want float64 // 0: measures nothing
	}{
		{"round 1: the first probe is the only own mapping", api.RoundInput{}, r, tr, 22},
		{"after a round of 5 mappings", api.RoundInput{Prev: mapped(5)}, r, tr, 12},
		{"counts the NAT did not see: the two probes", api.RoundInput{Prev: mapped(20)}, r, tr, 20},
		{"anchor on another IP: the two probes", api.RoundInput{}, r, other, 20},
		{"only the first probe: 10 steps in 0.4 s", api.RoundInput{}, onlyFirst, tr, 22.5},
		{"only the second probe", api.RoundInput{}, onlySecond, tr, 22},
		{"only one probe, no anchor to measure from", api.RoundInput{}, onlySecond, other, 0},
	} {
		l, ok := refreshRate(input{RoundInput: c.in}, 0, c.r, c.tr, 1)
		if ok != (c.want != 0) || l < c.want-0.1 || l > c.want+0.1 {
			t.Errorf("%s: rate %v %v, want %v", c.name, l, ok, c.want)
		}
	}
}

// A refresh that lost a probe still anchors: on its second
// mapping, or on its first past the second's own mapping, which the NAT
// made all the same.
func TestRefreshOneProbe(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.3")
	r := refreshOf(protocol.FamilyUDP4, ip, 40000, 40003, time.Second, 60*time.Millisecond)
	for _, c := range []struct {
		name      string
		first     bool
		second    bool
		port      uint16
		at        time.Duration
		before    int
		after     int
		hasRate   bool
		onAnother bool
	}{
		{name: "both", first: true, second: true, port: 40003, at: r.SecondAt, before: 1, hasRate: true},
		{name: "second only", second: true, port: 40003, at: r.SecondAt, before: 1},
		{name: "first only", first: true, port: 40000, at: r.FirstAt, after: 1},
	} {
		x := r
		if !c.first {
			x.First = netip.AddrPort{}
		}
		if !c.second {
			x.Second = netip.AddrPort{}
		}
		port, at, before, after := anchorNewest(x)
		if port != c.port || at != c.at || before != c.before || after != c.after {
			t.Errorf("%s: newest %d at %v (%d before, %d after)", c.name, port, at, before, after)
		}
		if _, ok := anchorRate(x, 1); ok != c.hasRate {
			t.Errorf("%s: pair rate %v", c.name, ok)
		}
		if !anchorOn(x, ip) || anchorOn(x, netip.MustParseAddr("203.0.113.4")) {
			t.Errorf("%s: on the wrong IP", c.name)
		}
	}
	if anchorOn(api.AnchorRefresh{Family: protocol.FamilyUDP4}, ip) {
		t.Error("a refresh without a probe anchors")
	}
}

// A seq_x_seq round after both sides refreshed aims each paired window at
// the peer's second refresh mapping, plus its Direct mappings of the
// round, plus the drift it measured until the fire time (kept short).
func TestRefreshPairedAnchor(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := seqTraits(f), seqTraits(f)
	b.Observed = observedFor(f, 6)
	b.PortAnchor = b.Observed.Port()
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	in := roundInput(cl, a, b, 1, nil)
	in.FireAt = 2 * time.Second
	plain := p.Round(in)
	at := in.FireAt - 500*time.Millisecond
	in.Refresh = [2][]api.AnchorRefresh{
		{refreshOf(f, a.Observed.Addr(), a.PortAnchor+40, a.PortAnchor+43, at, 100*time.Millisecond)},
		{refreshOf(f, b.Observed.Addr(), b.PortAnchor+60, b.PortAnchor+63, at, 100*time.Millisecond)},
	}
	dec := p.Round(in)
	for role, peer := range []protocol.Traits{b, a} {
		before, after := mustStageOf(t, plain.Sides[role][0], protocol.StagePredict), mustStageOf(t, dec.Sides[role][0], protocol.StagePredict)
		r := in.Refresh[1-role][0]
		pre := int(before.Anchor) - int(peer.PortAnchor) // the peer's Direct mappings of the round
		lambda, _ := refreshRate(input{RoundInput: in}, 1-role, r, peer, 1)
		want := int(r.Second.Port()) + pre + refreshDrift(lambda, r, in.FireAt+predictAt(dec.Sides[1-role][0]))
		if !after.Pair || int(after.Anchor) != want || after.Span != before.Span {
			t.Fatalf("role %d: anchor %d (span %d), want %d (span %d)", role, after.Anchor, after.Span, want, before.Span)
		}
	}
}

// A refresh reads the allocator off the NAT, so it supersedes the counted
// mappings: a round whose packets were lost before the NAT left
// counts the NAT never saw, and the anchor stays on the refresh. A refresh
// that lost its second probe anchors past that probe's own mapping.
func TestRefreshSupersedesCounts(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := seqTraits(f), seqTraits(f)
	b.Observed = observedFor(f, 6)
	b.PortAnchor = b.Observed.Port()
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	r1 := p.Round(roundInput(cl, a, b, 1, nil))
	prev := []api.RoundOutcome{{Round: 1, Variant: r1.Variant, Class: api.RoundNoContact, Budget: r1.Budget, Families: slices.Clone(r1.Families)}}
	prev[0].Families[0].Mapped = [2]int{22, 22} // the round's packets, as the coordinator counts them
	in := roundInput(cl, a, b, 2, prev)
	in.FireAt = 2 * time.Second
	counted := p.Round(in)
	for role, peer := range []protocol.Traits{b, a} {
		if st := mustStageOf(t, counted.Sides[role][0], protocol.StagePredict); int(st.Anchor) != int(peer.PortAnchor)+22 {
			t.Fatalf("role %d without a refresh: anchor %d, want the counted %d", role, st.Anchor, int(peer.PortAnchor)+22)
		}
	}
	// The NAT saw none of round 1: the refresh probes took the next ports.
	at := in.FireAt - 150*time.Millisecond
	in.Refresh = [2][]api.AnchorRefresh{
		{refreshOf(f, a.Observed.Addr(), a.PortAnchor+1, a.PortAnchor+2, at, 60*time.Millisecond)},
		{refreshOf(f, b.Observed.Addr(), b.PortAnchor+1, 0, at, 60*time.Millisecond)},
	}
	in.Refresh[1][0].Second = netip.AddrPort{} // the responder's second probe was lost
	dec := p.Round(in)
	for role, want := range []int{int(b.PortAnchor) + 1 + 1, int(a.PortAnchor) + 2} {
		if st := stageOf(dec.Sides[role][0], protocol.StagePredict); st == nil || !st.Pair || int(st.Anchor) != want {
			t.Errorf("role %d: predict %+v, want the paired anchor %d", role, st, want)
		}
	}
}

// Outside seq_x_seq the refresh replaces the probe's anchor and velocity:
// the window centres on the second refresh mapping extrapolated by the
// measured rate.
func TestRefreshPrediction(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := pdfTraits(f), seqTraits(f)
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	in := roundInput(cl, a, b, 1, nil)
	in.FireAt = 3 * time.Second
	in.Refresh[1] = []api.AnchorRefresh{refreshOf(f, b.Observed.Addr(), b.PortAnchor+100, b.PortAnchor+105, in.FireAt-600*time.Millisecond, 100*time.Millisecond)}
	dec := p.Round(in)
	pred := stageOf(dec.Sides[0][0], protocol.StagePredict)
	// 4 foreign steps in 100 ms: 40/s, 0.5 s to the fire time.
	if want := b.PortAnchor + 105 + 20; pred == nil || pred.Anchor != want {
		t.Fatalf("predict %+v, want anchor %d", pred, want)
	}
}

func TestRefreshWanted(t *testing.T) {
	f := protocol.FamilyUDP4
	var p DefaultPlanner
	seq := func(n int, ms int64, v float32) protocol.Traits {
		t := seqTraits(f)
		t.Observed = observedFor(f, n)
		t.PortAnchor, t.PortAnchorMs, t.PortVelocity = t.Observed.Port(), ms, v
		return t
	}
	noisy := func(t protocol.Traits) protocol.Traits {
		t.PortNoisy = true
		return t
	}
	down := func(t protocol.Traits) protocol.Traits {
		t.PortStep = -1
		return t
	}
	now := 2 * time.Second
	for _, c := range []struct {
		name    string
		a, b    protocol.Traits
		verdict bool // natprobe measured the pair as SeqRndVerdict holds
		want    [2]bool
	}{
		{"seq_x_seq quiet and fresh: paired, refreshed anyway", seq(3, 1800, 0), seq(6, 1700, 0), false, [2]bool{true, true}},
		{"seq_x_seq stale", seq(3, 1000, 0), seq(6, 1700, 0), false, [2]bool{true, true}},
		{"pdf_x_seq quiet and fresh", pdfTraits(f), seq(6, 1800, 0), false, [2]bool{false, false}},
		{"pdf_x_seq stale", pdfTraits(f), seq(6, 1000, 0), false, [2]bool{false, true}},
		{"pdf_x_seq velocity", pdfTraits(f), seq(6, 1800, 12), false, [2]bool{false, true}},
		{"pdf_x_seq downward velocity", pdfTraits(f), down(seq(6, 1800, -12)), false, [2]bool{false, true}},
		{"pdf_x_seq foreign ports between the probes", pdfTraits(f), noisy(seq(6, 1800, 0)), false, [2]bool{false, true}},
		{"seq_x_rnd: the RND side predicts the SEQ side", seq(3, 1000, 0), rndTraits(f), false, [2]bool{true, false}},
		{"seq_x_rnd under its verdict: hopeless, never refreshed", seq(3, 1000, 0), rndTraits(f), true, [2]bool{false, false}},
		{"open_x_edm: no prediction in round 1", openTraits(f), seq(6, 1000, 0), false, [2]bool{false, false}},
	} {
		cin := classifyInput(c.a, c.b)
		if c.verdict {
			cin.Measured = [2]protocol.PeerView{view(c.a), view(c.b)}
		}
		cl := p.Classify(cin)
		in := classified(roundInput(cl, c.a, c.b, 1, nil), cin)
		got := RefreshWanted(in, p.Round(in), now)
		for role := range 2 {
			if has := slices.Contains(got[role], f); has != c.want[role] {
				t.Errorf("%s: role %d wanted %v, want %v", c.name, role, has, c.want[role])
			}
		}
	}
}
