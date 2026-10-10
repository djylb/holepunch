package plan

import (
	"net/netip"
	"testing"
	"time"

	"github.com/djylb/holepunch/protocol"
)

// TestSideMappings counts a side's new NAT mappings: a Direct target
// on every socket that never sent to it, a LAN target never, every spray
// port.
func TestSideMappings(t *testing.T) {
	pub := []netip.AddrPort{netip.MustParseAddrPort("203.0.113.9:1000"), netip.MustParseAddrPort("203.0.113.9:1001")}
	lan := []netip.AddrPort{netip.MustParseAddrPort("192.168.1.9:1000")}
	fs := protocol.FamilySide{Sockets: 8, Stages: []protocol.Stage{
		{Kind: protocol.StageDirect, Targets: lan, Repeats: 2},
		{Kind: protocol.StageDirect, Targets: pub, Repeats: 2},
		{Kind: protocol.StagePredict, Span: 128},
		{Kind: protocol.StageRandom, Count: 5},
	}}
	for _, c := range []struct {
		sent   func(netip.AddrPort) int
		direct int
	}{
		{nil, 8 * 2},
		{func(netip.AddrPort) int { return 1 }, 7 * 2},
		{func(t netip.AddrPort) int { return map[netip.AddrPort]int{pub[0]: 8}[t] }, 8},
		{func(netip.AddrPort) int { return 32 }, 0},
	} {
		if d, s := SideMappings(fs, c.sent); d != c.direct || s != 133 {
			t.Errorf("mappings %d + %d, want %d + 133", d, s, c.direct)
		}
	}
}

// seqSeqInput is a seq_x_seq round input between two APDM peers as natprobe
// reports them (apdmView): the initiator's anchor at 40003, the
// responder's at 50012.
func seqSeqInput(t *testing.T, round int, prev []RoundOutcome) (RoundInput, [2]uint16) {
	t.Helper()
	f := protocol.FamilyUDP4
	a, b := seqTraits(f), seqTraits(f)
	b.Observed = netip.MustParseAddrPort("203.0.113.7:50000")
	b.PortAnchor = 50012
	cin := classifyInput(a, b)
	cin.Initiator, cin.Responder = apdmView(a), apdmView(b)
	var p DefaultPlanner
	cl := p.Classify(cin)
	if cl.PairClass != PairSeqSeq {
		t.Fatalf("pair class %q", cl.PairClass)
	}
	in := roundInput(cl, a, b, round, prev)
	in.Views = [2]protocol.PeerView{cin.Initiator, cin.Responder}
	in.SandwichOK = true
	in.FireAt = 5 * time.Second
	return in, [2]uint16{b.PortAnchor, a.PortAnchor} // what each role predicts
}

func predictStage(t *testing.T, fs protocol.FamilySide) protocol.Stage {
	t.Helper()
	for _, st := range fs.Stages {
		if st.Kind == protocol.StagePredict {
			return st
		}
	}
	t.Fatalf("no predict stage: %s", describe(fs))
	return protocol.Stage{}
}

// TestSeqPairWindows: in seq_x_seq each side's predict stage is paired, has
// the peer's span and starts after the peer's anchor plus the peer's
// mappings since — its Direct ones this round and every earlier round's
// FamilyRound.Mapped; there is no sandwich and no extrapolation by
// PortVelocity. The decision records each side's centre.
func TestSeqPairWindows(t *testing.T) {
	var p DefaultPlanner
	in, anchors := seqSeqInput(t, 1, nil)
	for r := range 2 {
		tr := &in.Views[r].Families[0].Traits
		tr.PortVelocity, tr.PortAnchorMs = 50, 1000 // would move an extrapolated window by 200 ports
	}
	dec := p.Round(in)
	var spans [2]uint16
	for r := range 2 {
		st := predictStage(t, dec.Sides[r][0])
		// two Direct targets (the peer's primary and second socket) on one socket
		if !st.Pair || st.Anchor != anchors[r]+2 || len(st.Steps) != 1 || st.Steps[0] != 1 {
			t.Fatalf("round 1 role %d: %+v, want paired anchor %d", r, st, anchors[r]+2)
		}
		spans[r] = st.Span
		if sandwichOf(dec)[r] {
			t.Errorf("round 1 role %d: sandwich in seq_x_seq", r)
		}
		if c := dec.Families[0].Center[r]; c != st.Anchor+1 {
			t.Errorf("round 1 role %d: centre %d, want %d", r, c, st.Anchor+1)
		}
	}
	if spans[0] != spans[1] || spans[0] != 16 {
		t.Errorf("spans %v, want 16 each", spans)
	}
	assertEmittable(t, dec)

	// Round 2: the responder made 18 mappings in round 1, the initiator 20.
	fr := dec.Families
	fr[0].Mapped = [2]int{20, 18}
	in2, _ := seqSeqInput(t, 2, []RoundOutcome{{Round: 1, Variant: dec.Variant, Class: RCNoContact, Budget: dec.Budget, Families: fr}})
	dec2 := p.Round(in2)
	for r, moved := range [2]uint16{18, 20} {
		st := predictStage(t, dec2.Sides[r][0])
		if !st.Pair || st.Anchor != anchors[r]+moved {
			t.Fatalf("round 2 role %d: anchor %d, want %d", r, st.Anchor, anchors[r]+moved)
		}
	}
	assertEmittable(t, dec2)
}

// TestPairSpansEqual: when one side's grant is short, the other side's span
// is cut to it, and its MaxPackets with it.
func TestPairSpansEqual(t *testing.T) {
	var p DefaultPlanner
	in, _ := seqSeqInput(t, 1, nil)
	in.Recent10sDistinct = [2]int{0, 64 - 2 - 10} // the responder's 10 s window leaves 10 spray ports
	dec := p.Round(in)
	a, b := predictStage(t, dec.Sides[0][0]), predictStage(t, dec.Sides[1][0])
	if a.Span != 10 || b.Span != 10 {
		t.Fatalf("spans %d / %d, want 10 each", a.Span, b.Span)
	}
	assertEmittable(t, dec)
}

// TestPairAnchor: the probe's anchor plus every earlier round's mappings,
// or a punch-time sample plus the rounds after its own, whichever is
// further along the allocator — across the 65535 → 1024 wrap and for a
// negative step; a sample on another IP (a rebound NAT) is the only
// anchor there.
func TestPairAnchor(t *testing.T) {
	f := protocol.FamilyUDP4
	tr := seqTraits(f) // anchor 40003 on 203.0.113.3
	ip := tr.Observed.Addr()
	prev := []RoundOutcome{
		{Round: 1, Families: []FamilyRound{{Family: f, Mapped: [2]int{0, 17}}}},
		{Round: 2, Families: []FamilyRound{{Family: f, Mapped: [2]int{0, 48}}}},
	}
	sample := func(port uint16, round int) MappingSample {
		return MappingSample{Addr: netip.AddrPortFrom(ip, port), Round: round}
	}
	cases := []struct {
		name    string
		tr      protocol.Traits
		samples []MappingSample
		ip      netip.Addr
		step    int
		want    uint16
	}{
		{"probe anchor", tr, nil, ip, 1, 40003 + 17 + 48 + 2},
		{"sample behind the count", tr, []MappingSample{sample(40010, 1)}, ip, 1, 40003 + 17 + 48 + 2},
		{"sample ahead (foreign mappings)", tr, []MappingSample{sample(40050, 1)}, ip, 1, 40050 + 48 + 2},
		{"sample of the last round", tr, []MappingSample{sample(40100, 2)}, ip, 1, 40100 + 2},
		{"wrap", func() protocol.Traits { w := tr; w.PortAnchor = 65500; return w }(), nil, ip, 1, wrapPort(65500 + 67)},
		{"sample past the wrap", func() protocol.Traits { w := tr; w.PortAnchor = 65500; return w }(),
			[]MappingSample{sample(1100, 2)}, ip, 1, 1102},
		{"negative step", func() protocol.Traits { w := tr; w.PortStep = -1; return w }(), nil, ip, -1, 40003 - 67},
		{"rebound to another IP", tr, []MappingSample{{Addr: netip.MustParseAddrPort("198.51.100.4:7000"), Round: 2}},
			netip.MustParseAddr("198.51.100.4"), 1, 7002},
	}
	for _, c := range cases {
		in := RoundInput{Prev: prev}
		in.Mappings[1] = c.samples
		got, ok := pairAnchor(in, 1, f, c.ip, c.tr, c.step, 2, 0)
		if !ok || got != c.want {
			t.Errorf("%s: anchor %d %v, want %d", c.name, got, ok, c.want)
		}
	}
	if _, ok := pairAnchor(RoundInput{}, 1, f, netip.MustParseAddr("198.51.100.4"), tr, 1, 0, 0); ok {
		t.Error("an anchor on an IP neither the probe nor a sample saw")
	}
}

// TestSandwichOnlyTowardEndpointIndependent: a SEQ side gets the sandwich
// only when its peer is OPEN or PDF; its predict stage toward an
// OPEN/PDF peer is no paired one.
func TestSandwichOnlyTowardEndpointIndependent(t *testing.T) {
	f := protocol.FamilyUDP4
	var p DefaultPlanner
	for _, c := range []struct {
		a, b protocol.Traits
		want [2]bool
	}{
		{openTraits(f), seqTraits(f), [2]bool{false, true}},
		{pdfTraits(f), seqTraits(f), [2]bool{false, true}},
		{seqTraits(f), seqTraits(f), [2]bool{}},
		{seqTraits(f), rndTraits(f), [2]bool{}},
	} {
		cl := p.Classify(classifyInput(c.a, c.b))
		in := roundInput(cl, c.a, c.b, 1, nil)
		in.SandwichOK = true
		dec := p.Round(in)
		if sandwichOf(dec) != c.want {
			t.Errorf("%s: sandwich %v, want %v", cl.PairClass, sandwichOf(dec), c.want)
		}
		for r := range 2 {
			for _, st := range dec.Sides[r][0].Stages {
				if st.Pair && cl.PairClass != PairSeqSeq {
					t.Errorf("%s: a paired stage %+v", cl.PairClass, st)
				}
			}
		}
	}
}
