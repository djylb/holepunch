package plan

import (
	"net/netip"
	"slices"
	"testing"

	api "github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

// directOf lists the Direct stages' targets of a family side, with their
// repeats.
func directOf(fs protocol.FamilySide) map[netip.AddrPort]uint8 {
	out := map[netip.AddrPort]uint8{}
	for _, st := range fs.Stages {
		if st.Kind == protocol.StageDirect {
			for _, a := range st.Targets {
				out[a] = max(out[a], st.Repeats)
			}
		}
	}
	return out
}

// withLocalPort adds the peer's local-port candidate to a view.
func withLocalPort(v protocol.PeerView, port uint16) (protocol.PeerView, netip.AddrPort) {
	g := netip.AddrPortFrom(v.Families[0].Traits.Observed.Addr(), port)
	v.Families[0].Endpoints = append(slices.Clone(v.Families[0].Endpoints), protocol.Endpoint{Addr: g, Source: protocol.EndpointLocalPort})
	return v, g
}

// TestLocalPortGuess checks the local-port guess: the peer's primary socket at
// its local port on the verified IP is an extra Direct target of D(2) beside
// the round's Direct stage; not for a MultiExit peer, and not once the peer's
// real source was heard.
func TestLocalPortGuess(t *testing.T) {
	a, b := mediumEIM(1), mediumEIM(2)
	cl := DefaultPlanner{}.Classify(classifyInput(a, b))
	in := roundInput(cl, a, b, 1, nil)
	var guess netip.AddrPort
	in.Views[0], guess = withLocalPort(in.Views[0], 40000)
	dec := DefaultPlanner{}.Round(in)
	got := directOf(dec.Sides[1][0])
	if got[guess] != guessRepeats || got[a.Observed] == 0 {
		t.Fatalf("responder's Direct targets %v, want %v at D(%d) beside %v", got, guess, guessRepeats, a.Observed)
	}
	if g := directOf(dec.Sides[0][0]); len(g) != 1 {
		t.Fatalf("initiator's Direct targets %v: the responder has no guess", g)
	}

	multi := in
	multi.Views[0].Families = slices.Clone(in.Views[0].Families)
	multi.Views[0].Families[0].Traits.MultiExit = true
	if g := directOf(DefaultPlanner{}.Round(multi).Sides[1][0]); g[guess] != 0 {
		t.Fatalf("MultiExit peer: %v", g)
	}

	heard := netip.AddrPortFrom(a.Observed.Addr(), 40007)
	in.Round, in.Evidence.SeenFrom[1] = 2, []netip.AddrPort{heard, netip.MustParseAddrPort("198.18.0.9:1234")}
	in.Prev = []api.RoundOutcome{{Round: 1, Variant: dec.Variant, Class: api.RoundOneWay, Budget: dec.Budget, Rescue: true}}
	in.RescueUsed = true
	g := directOf(DefaultPlanner{}.Round(in).Sides[1][0])
	if len(g) != 1 || g[heard] == 0 {
		t.Fatalf("after the peer was heard at %v: Direct targets %v", heard, g)
	}
}

// oneWay is an outcome of family udp4 in which side seer heard its peer
// (and the other side did not), or nobody heard when seer < 0.
func oneWay(round int, dec api.RoundDecision, seer int, rescue bool) api.RoundOutcome {
	o := api.RoundOutcome{Round: round, Variant: dec.Variant, Class: api.RoundNoContact, Budget: dec.Budget, Rescue: rescue, Families: slices.Clone(dec.Families)}
	for i := range o.Families {
		o.Families[i].NoContact = seer < 0
		if seer >= 0 {
			o.Families[i].Heard[seer] = true
			o.Class = api.RoundOneWay
		}
	}
	return o
}

// TestOneWaySwitch checks the one-way switch: an easy pair whose responder
// heard the initiator twice — a rescue round that found nothing in between —
// while the initiator never heard it becomes a PDF×RND pair with the responder
// as the random side: its sockets aim at the source it heard, the initiator
// sprays its IP; an Interactive session runs the conservative birthday rounds,
// a Background one the slow birthday.
func TestOneWaySwitch(t *testing.T) {
	a, b := mediumEIM(1), mediumEIM(2)
	heard := netip.AddrPortFrom(a.Observed.Addr(), 40007)
	for _, bg := range []bool{false, true} {
		in := classifyInput(a, b)
		if bg {
			in.Mode = protocol.ModeBackground
		}
		cl := DefaultPlanner{}.Classify(in)
		var prev []api.RoundOutcome
		var names []string
		var last api.RoundDecision
		rescued := false
		for round := 1; round <= 4; round++ {
			ri := classified(roundInput(cl, a, b, round, prev), in)
			ri.MaxRounds, ri.RescueUsed, ri.HandshakeMs = 6, rescued, 60000
			ri.Remaining = 60e9
			if round > 1 {
				ri.Evidence.SeenFrom[1] = []netip.AddrPort{heard}
			}
			last = DefaultPlanner{}.Round(ri)
			if last.Stop != "" {
				t.Fatalf("background %v, round %d: stop %s", bg, round, last.Stop)
			}
			names = append(names, last.VariantName)
			rescued = rescued || last.Rescue
			switch {
			case last.Rescue:
				prev = append(prev, oneWay(round, last, -1, true))
			default:
				prev = append(prev, oneWay(round, last, 1, false))
			}
		}
		want := []string{"easy_r1_direct", "rescue", "easy_r2_ttl", "pdf_x_rnd_r2_birthday"}
		if bg {
			want[3] = "pdf_x_rnd_slow"
		}
		if !slices.Equal(names, want) {
			t.Fatalf("background %v: rounds %v, want %v", bg, names, want)
		}
		rs, is := last.Sides[1][0], last.Sides[0][0]
		if rs.Sockets < 2 || len(directOf(rs)) != 1 || directOf(rs)[heard] == 0 {
			t.Fatalf("background %v: random side %d sockets, Direct %v; want several aimed at %v", bg, rs.Sockets, directOf(rs), heard)
		}
		if !slices.ContainsFunc(is.Stages, func(st protocol.Stage) bool { return st.Kind == protocol.StageRandom && st.IP == b.Observed.Addr() }) {
			t.Fatalf("background %v: the silent side does not spray the hearer's IP: %+v", bg, is.Stages)
		}
	}
}

// TestOneWaySeer checks the evidence oneWaySeer reads: two one-way rounds
// of the same hearer, the other side never hearing.
func TestOneWaySeer(t *testing.T) {
	r := func(h0, h1 bool) api.RoundOutcome {
		return api.RoundOutcome{Families: []api.FamilyRound{{Family: protocol.FamilyUDP4, Heard: [2]bool{h0, h1}}}}
	}
	for _, c := range []struct {
		name string
		prev []api.RoundOutcome
		seer int
		from int
		ok   bool
	}{
		{"twice", []api.RoundOutcome{r(false, true), r(false, false), r(false, true)}, 1, 3, true},
		{"once", []api.RoundOutcome{r(true, false), r(false, false)}, 0, 0, false},
		{"other heard once", []api.RoundOutcome{r(false, true), r(true, true), r(false, true)}, 0, 0, false},
		{"both ways", []api.RoundOutcome{r(true, false), r(false, true), r(true, false), r(false, true)}, 0, 0, false},
		{"initiator", []api.RoundOutcome{r(true, false), r(true, false), r(false, false)}, 0, 2, true},
	} {
		seer, from, ok := oneWaySeer(c.prev, protocol.FamilyUDP4)
		if ok != c.ok || ok && (seer != c.seer || from != c.from) {
			t.Errorf("%s: %d %d %v, want %d %d %v", c.name, seer, from, ok, c.seer, c.from, c.ok)
		}
	}
}

// TestNoRescueForRandomHearer checks the one-way switch: when the random side of a
// PDF×RND pair heard the PDF side, the next round is the ladder's birthday
// round, not a rescue that only replies, and its sockets aim at the source
// heard.
func TestNoRescueForRandomHearer(t *testing.T) {
	pdf, rnd := pdfTraits(protocol.FamilyUDP4), rndTraits(protocol.FamilyUDP4)
	cl := DefaultPlanner{}.Classify(classifyInput(pdf, rnd))
	if cl.PairClass != PairPDFRnd || cl.SideA != protocol.RoleInitiator {
		t.Fatalf("class %s, A %s", cl.PairClass, cl.SideA)
	}
	in := roundInput(cl, pdf, rnd, 1, nil)
	in.Policy.Budget.Birthday = protocol.BirthdayConservative
	dec := DefaultPlanner{}.Round(in)
	heard := netip.AddrPortFrom(pdf.Observed.Addr(), 40007)
	o := oneWay(1, dec, 1, false)
	o.SeenFrom[1] = []netip.AddrPort{heard}
	in = roundInput(cl, pdf, rnd, 2, []api.RoundOutcome{o})
	in.Policy.Budget.Birthday = protocol.BirthdayConservative
	in.Evidence.SeenFrom[1] = []netip.AddrPort{heard}
	dec = DefaultPlanner{}.Round(in)
	if dec.Rescue || dec.VariantName != "pdf_x_rnd_r2_birthday" {
		t.Fatalf("round 2: %s (rescue %v)", dec.VariantName, dec.Rescue)
	}
	if g := directOf(dec.Sides[1][0]); len(g) != 1 || g[heard] == 0 {
		t.Fatalf("random side's Direct targets %v", g)
	}
	// The PDF side heard instead: the rescue runs as before.
	o = oneWay(1, dec, 0, false)
	o.SeenFrom[0] = []netip.AddrPort{rnd.Observed}
	in = roundInput(cl, pdf, rnd, 2, []api.RoundOutcome{o})
	if dec := (DefaultPlanner{}).Round(in); !dec.Rescue {
		t.Fatalf("PDF side heard: %s", dec.VariantName)
	}
}
