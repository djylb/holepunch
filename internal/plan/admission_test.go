package plan

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"github.com/djylb/holepunch/protocol"
)

// clientModel is the client's target admission and send schedule for one family
// of one side, as the root package implements them (newWorker, admit, schedule
// and directItems in workers.go and rounds.go). The plan package cannot import
// the client, so the model restates it; every planner output must run under it
// unchanged.
type clientModel struct {
	fam        protocol.Family
	verified   map[netip.Addr]bool
	endpoints  map[netip.AddrPort]bool
	lan        map[netip.Addr]bool // the peer's LAN IPs, same LAN only, at most 4
	overlay    map[netip.Addr]bool // the peer's overlay IPs, shared overlay only, at most 2
	reported   map[netip.Addr]bool // unverified family: the peer's global IPs, at most 4
	unverified bool
}

// Client admission constants (root package workers.go).
const (
	clientLANTargets        = 4
	clientOverlayTargets    = 2
	clientLANPackets        = 2
	clientUnverifiedTargets = 4
	clientUnverifiedPackets = 8
)

// newClientModel builds the admission state of a side whose summary carries
// the peer view peer and the pair facts pair (newWorker).
func newClientModel(fam protocol.Family, peer protocol.PeerView, pair protocol.PairFacts) clientModel {
	m := clientModel{fam: fam, verified: map[netip.Addr]bool{}, endpoints: map[netip.AddrPort]bool{},
		lan: map[netip.Addr]bool{}, overlay: map[netip.Addr]bool{}, reported: map[netip.Addr]bool{}, unverified: pair.Unverified[fam]}
	fv, _ := findFamily(peer, fam)
	sameLAN := pair.LikelySameLAN[fam]
	for _, e := range fv.Endpoints {
		ap := canonAP(e.Addr)
		m.endpoints[ap] = true
		a := ap.Addr()
		switch {
		case e.Source == protocol.EndpointOverlay:
			if pair.SharedOverlay[fam] && len(m.overlay) < clientOverlayTargets {
				m.overlay[a] = true
			}
		case e.Verified:
			m.verified[a] = true
		case e.Source == protocol.EndpointLAN && sameLAN && len(m.lan) < clientLANTargets && privateAddr(a):
			m.lan[a] = true
		case m.unverified && a.IsGlobalUnicast() && !privateAddr(a) && len(m.reported) < clientUnverifiedTargets:
			m.reported[a] = true
		}
	}
	return m
}

func canonAP(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port())
}

// unusableAddr is the client's netaddr.Unusable after canonicalisation (the
// zone is gone, so every IPv6 link-local address is unusable).
func unusableAddr(a netip.Addr) bool {
	return !a.IsValid() || a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() ||
		a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) || a.Is6() && a.IsLinkLocalUnicast()
}

// admit is the client's admit: whether ap may be aimed at by a stage of
// kind, and the per-round packet cap of a LAN or unverified target.
func (m clientModel) admit(ap netip.AddrPort, kind protocol.StageKind) (ok bool, perTarget int) {
	ap = canonAP(ap)
	a := ap.Addr()
	if !m.fam.Matches(a) || unusableAddr(a) || ap.Port() == 0 {
		return false, 0
	}
	if kind == protocol.StageDirect && (ap.Port() < 1024 || SensitivePort(ap.Port())) && !m.endpoints[ap] {
		return false, 0
	}
	switch {
	case m.verified[a]:
		if privateAddr(a) && kind != protocol.StageDirect {
			return false, 0
		}
		return true, 0
	case (m.lan[a] || m.overlay[a]) && kind == protocol.StageDirect:
		return true, clientLANPackets
	case m.unverified && m.reported[a] && kind == protocol.StageDirect:
		return true, clientUnverifiedPackets
	}
	return false, 0
}

// clientRun is what the client does with one family side.
type clientRun struct {
	declared int // packets the client schedules: Direct as sent, predict span, random count
	expanded int // packets it actually sends: Direct as sent, predict and random as ExpandStage yields
	refused  []string
	perLAN   map[netip.AddrPort]int // packets per LAN target
	perUnver map[netip.AddrPort]int // packets per unverified target
}

// run is the client's schedule of fs (schedule, directItems, sprayItems): a
// LAN or unverified target is sent from the primary socket only, at most its
// per-round cap per stage; a verified one from every socket.
func (m clientModel) run(fs protocol.FamilySide) clientRun {
	cr := clientRun{perLAN: map[netip.AddrPort]int{}, perUnver: map[netip.AddrPort]int{}}
	if fs.Role == protocol.SideReplyOnly {
		return cr
	}
	sockets := max(int(fs.Sockets), 1)
	for i, st := range fs.Stages {
		switch st.Kind {
		case protocol.StageDirect:
			for _, t := range st.Targets {
				ok, per := m.admit(t, protocol.StageDirect)
				if !ok {
					cr.refused = append(cr.refused, fmt.Sprintf("direct %v", t))
					continue
				}
				reps, socks := max(int(st.Repeats), 1), sockets
				if per > 0 {
					reps, socks = min(reps, per), 1
				}
				switch {
				case per > 0 && (m.lan[canonAP(t).Addr()] || m.overlay[canonAP(t).Addr()]):
					cr.perLAN[t] += reps
				case per > 0:
					cr.perUnver[t] += reps
				}
				cr.declared += reps * socks
				cr.expanded += reps * socks
			}
		case protocol.StageFresh, protocol.StageFreshPeer:
			// Fresh sockets aim at verified endpoints or pair up on the
			// peer's verified IP: a prediction, as predict is.
			for _, t := range st.Targets {
				if ok, _ := m.admit(t, protocol.StageDirect); !ok {
					cr.refused = append(cr.refused, fmt.Sprintf("%s %v", st.Kind, t))
				}
			}
			if st.IP.IsValid() {
				if ok, _ := m.admit(netip.AddrPortFrom(st.IP, 1024), protocol.StagePredict); !ok || m.unverified {
					cr.refused = append(cr.refused, fmt.Sprintf("%s %v", st.Kind, st.IP))
				}
			}
			cr.declared += FreshPackets(st)
			cr.expanded += FreshPackets(st)
		case protocol.StagePredict, protocol.StageRandom:
			if m.unverified {
				cr.refused = append(cr.refused, fmt.Sprintf("%s in an unverified family", st.Kind))
				continue
			}
			if ok, _ := m.admit(netip.AddrPortFrom(st.IP, 1024), st.Kind); !ok {
				cr.refused = append(cr.refused, fmt.Sprintf("%s %v", st.Kind, st.IP))
				continue
			}
			if st.Kind == protocol.StagePredict {
				cr.declared += int(st.Span)
			} else {
				cr.declared += int(st.Count)
			}
			cr.expanded += len(ExpandStage(st, ExpandInput{Seed: [8]byte{7, byte(i)}, StageIndex: i}))
		}
	}
	return cr
}

// wireView is the view of side p its peer receives (coord's
// peerViewLocked): a private LAN address only to a peer on the same LAN, a
// private port mapping (an upstream-LAN candidate) only to a peer behind the
// same public IP, an overlay address only to a peer that has one too.
func wireView(v protocol.PeerView, pair protocol.PairFacts) protocol.PeerView {
	out := protocol.PeerView{}
	for _, fv := range v.Families {
		fv.Endpoints = slices.DeleteFunc(slices.Clone(fv.Endpoints), func(e protocol.Endpoint) bool {
			if e.Source == protocol.EndpointOverlay {
				return !pair.SharedOverlay[fv.Family]
			}
			if !privateAddr(e.Addr.Addr().Unmap()) || e.Verified {
				return false
			}
			switch e.Source {
			case protocol.EndpointLAN:
				return !pair.LikelySameLAN[fv.Family]
			case protocol.EndpointPortmap:
				return !pair.SamePublicIP[fv.Family]
			}
			return false
		})
		out.Families = append(out.Families, fv)
	}
	return out
}

// checkAdmitted runs every family side of dec under the clients' admission:
// no target is refused; MaxPackets is exactly what the client schedules and
// at least what it sends; a LAN target gets at most two packets
// and an unverified one at most eight in the round, never in a stage with
// public targets; an unverified family has at most maxTargets distinct
// targets, all Direct, on one socket, and MaxPackets ≤ 8 × targets.
func checkAdmitted(t *testing.T, label string, dec RoundDecision, views [2]protocol.PeerView, pair protocol.PairFacts, maxTargets int) {
	t.Helper()
	for r := range 2 {
		peer := wireView(views[1-r], pair)
		for _, fs := range dec.Sides[r] {
			m := newClientModel(fs.Family, peer, pair)
			cr := m.run(fs)
			where := fmt.Sprintf("%s round %s role %d %s", label, roundOf(dec), r, describe(fs))
			if len(cr.refused) > 0 {
				t.Errorf("%s: the client refuses %v", where, cr.refused)
			}
			if fs.Role != protocol.SideReplyOnly && cr.declared != int(fs.MaxPackets) {
				t.Errorf("%s: the client schedules %d packets, MaxPackets %d", where, cr.declared, fs.MaxPackets)
			}
			if cr.expanded > int(fs.MaxPackets) && fs.Role != protocol.SideReplyOnly {
				t.Errorf("%s: the client sends %d packets > MaxPackets %d", where, cr.expanded, fs.MaxPackets)
			}
			for a, n := range cr.perLAN {
				if n > lanRepeats {
					t.Errorf("%s: LAN target %v gets %d packets", where, a, n)
				}
			}
			for a, n := range cr.perUnver {
				if n > maxUnverifiedRepeats {
					t.Errorf("%s: unverified target %v gets %d packets", where, a, n)
				}
			}
			for _, st := range fs.Stages {
				lan, pub := 0, 0
				for _, a := range st.Targets {
					if _, ok := cr.perLAN[a]; ok {
						lan++
					} else {
						pub++
					}
				}
				if lan > 0 && (pub > 0 || lan > maxLANTargets+maxOverlayTargets || st.Repeats > lanRepeats) {
					t.Errorf("%s: LAN stage %+v", where, st)
				}
			}
			if !pair.Unverified[fs.Family] || fs.Role == protocol.SideReplyOnly {
				continue
			}
			if len(cr.perUnver) > maxTargets || fs.Sockets != 1 || int(fs.MaxPackets) > maxUnverifiedRepeats*(len(cr.perUnver)+len(cr.perLAN)) {
				t.Errorf("%s: unverified family over its limits (%d targets, max %d)", where, len(cr.perUnver), maxTargets)
			}
		}
	}
}

func roundOf(dec RoundDecision) string {
	if dec.Rescue {
		return "rescue"
	}
	return dec.VariantName
}

// Addresses of the admission scenarios.
var (
	sharedPub4 = netip.MustParseAddr("203.0.113.50")
	upstream4  = netip.MustParseAddrPort("100.64.5.6:41000")
)

// selfV6 is side n's IPv6 family as a coordinator without an IPv6 observer
// builds it from the report (coord's selfFamilyView): no row, the
// primary socket's address and the host's other addresses at its port, as
// LAN endpoints, none verified; provisional traits.
func selfV6(n int, tr protocol.Traits) protocol.FamilyView {
	port := uint16(41000 + n)
	tr.Family, tr.Samples = protocol.FamilyUDP6, 1
	fv := protocol.FamilyView{Family: protocol.FamilyUDP6, Traits: tr}
	for _, a := range []string{fmt.Sprintf("2001:db8:%d::10", n), fmt.Sprintf("2001:db8:%d::11", n), fmt.Sprintf("fd00:%d::10", n)} {
		fv.Endpoints = append(fv.Endpoints, protocol.Endpoint{Addr: netip.AddrPortFrom(netip.MustParseAddr(a), port),
			Source: protocol.EndpointLAN, Socket: 0x80})
	}
	return fv
}

// relayOnlyV4 is side n's IPv4 family in the relay-only mode: the
// client's own probe rows and STUN rows on five public IPs, two ports each,
// and its private address — eleven endpoints, a view holds twelve at most;
// nothing verified.
func relayOnlyV4(n int, tr protocol.Traits) protocol.FamilyView {
	tr.Family = protocol.FamilyUDP4
	fv := protocol.FamilyView{Family: protocol.FamilyUDP4, Traits: tr}
	for ip := range 5 {
		for port := range 2 {
			src := protocol.EndpointServer
			if ip > 0 {
				src = protocol.EndpointSTUN
			}
			fv.Endpoints = append(fv.Endpoints, protocol.Endpoint{Source: src,
				Addr: netip.MustParseAddrPort(fmt.Sprintf("198.51.%d.%d:%d", 100+n, 10+ip, 42000+port))})
		}
	}
	fv.Endpoints = append(fv.Endpoints, protocol.Endpoint{Addr: netip.MustParseAddrPort(fmt.Sprintf("10.0.%d.2:42000", n)), Source: protocol.EndpointLAN})
	return fv
}

// behindShared is side n's IPv4 family behind the shared public IP: the
// realistic verified mappings, then its LAN endpoints (primary and sibling
// on one address, four more addresses — a client keeps four LAN IPs — and an
// IPv4 link-local one) on lanNet, and an upstream-LAN candidate when
// portmap is set.
func behindShared(n int, tr protocol.Traits, lanNet string, portmap bool) protocol.FamilyView {
	tr.Observed = netip.AddrPortFrom(sharedPub4, uint16(40000+10*n))
	tr.PortAnchor, tr.PublicIP = tr.Observed.Port(), sharedPub4
	fv := realisticView(tr).Families[0]
	for i, a := range []string{lanNet + ".10:40000", lanNet + ".10:40001", lanNet + ".11:40000", lanNet + ".12:40000",
		lanNet + ".13:40000", lanNet + ".14:40000", "169.254.0.9:40000"} {
		fv.Endpoints = append(fv.Endpoints, protocol.Endpoint{Addr: netip.MustParseAddrPort(a), Source: protocol.EndpointLAN, Socket: uint8(i)})
	}
	if portmap {
		fv.Endpoints = append(fv.Endpoints, protocol.Endpoint{Addr: upstream4, Source: protocol.EndpointPortmap})
	}
	return fv
}

// admissionCase is one shared-network topology with the views and pair facts the
// coordinator hands the planner.
type admissionCase struct {
	name       string
	views      [2]protocol.PeerView
	pair       protocol.PairFacts
	maxTargets int // an unverified family's target limit
}

// admissionCase returns the case called name.
func admissionCaseNamed(t *testing.T, name string) admissionCase {
	t.Helper()
	for _, c := range admissionCases() {
		if c.name == name {
			return c
		}
	}
	t.Fatalf("no case %s", name)
	return admissionCase{}
}

func admissionCases() []admissionCase {
	u4, u6 := protocol.FamilyUDP4, protocol.FamilyUDP6
	both := []protocol.Family{u6, u4}
	cats := []struct {
		name string
		a, b func(protocol.Family) protocol.Traits
	}{
		{"easy", openTraits, pdfTraits},
		{"pdf_x_seq", pdfTraits, seqTraits},
		{"pdf_x_rnd", pdfTraits, rndTraits},
		{"seq_x_rnd", seqTraits, rndTraits},
		{"rnd_x_rnd", rndTraits, rndTraits},
	}
	var out []admissionCase
	for _, c := range cats {
		a4, b4 := c.a(u4), c.b(u4)
		// The server observes IPv4 only and both hosts have global
		// IPv6 addresses; the IPv6 traits are the clients' own guesses.
		out = append(out, admissionCase{
			name: "unverified_v6/" + c.name,
			views: [2]protocol.PeerView{
				{Families: []protocol.FamilyView{selfV6(1, c.a(u6)), realisticView(a4).Families[0]}},
				{Families: []protocol.FamilyView{selfV6(2, c.b(u6)), realisticView(b4).Families[0]}},
			},
			pair:       protocol.PairFacts{SharedFamilies: both, Unverified: map[protocol.Family]bool{u6: true}},
			maxTargets: maxUnverifiedTargets,
		})
		// No registry: every family is unverified.
		out = append(out, admissionCase{
			name: "relay_only/" + c.name,
			views: [2]protocol.PeerView{
				{Families: []protocol.FamilyView{selfV6(1, c.a(u6)), relayOnlyV4(1, a4)}},
				{Families: []protocol.FamilyView{selfV6(2, c.b(u6)), relayOnlyV4(2, b4)}},
			},
			pair:       protocol.PairFacts{SharedFamilies: both, Unverified: map[protocol.Family]bool{u6: true, u4: true}},
			maxTargets: maxRelayOnlyTargets,
		})
		// One LAN behind one NAT.
		out = append(out, admissionCase{
			name: "same_lan/" + c.name,
			views: [2]protocol.PeerView{
				{Families: []protocol.FamilyView{behindShared(1, a4, "192.168.1", false)}},
				{Families: []protocol.FamilyView{behindShared(2, b4, "192.168.1", false)}},
			},
			pair: protocol.PairFacts{SharedFamilies: []protocol.Family{u4},
				SamePublicIP: map[protocol.Family]bool{u4: true}, LikelySameLAN: map[protocol.Family]bool{u4: true}},
		})
		// One upstream NAT, two LANs, each side with a private port
		// mapping of its home router.
		out = append(out, admissionCase{
			name: "upstream/" + c.name,
			views: [2]protocol.PeerView{
				{Families: []protocol.FamilyView{behindShared(1, a4, "192.168.1", true)}},
				{Families: []protocol.FamilyView{behindShared(2, b4, "192.168.2", true)}},
			},
			pair: protocol.PairFacts{SharedFamilies: []protocol.Family{u4}, SamePublicIP: map[protocol.Family]bool{u4: true}},
		})
	}
	return out
}

// TestPlansAdmittedByClient: in the three shared-network situations — a family the
// server cannot verify (and the relay-only mode), one shared LAN, and two
// LANs behind one upstream NAT — every round of every ladder, the rescue
// round included, runs under the clients' admission exactly as planned.
func TestPlansAdmittedByClient(t *testing.T) {
	var p DefaultPlanner
	for _, c := range admissionCases() {
		t.Run(c.name, func(t *testing.T) {
			ci := ClassifyInput{Initiator: c.views[0], Responder: c.views[1], Pair: c.pair, Policy: protocol.Policy{Budget: protocol.DefaultBudget()}}
			cl := p.Classify(ci)
			if cl.Reject != "" {
				t.Fatalf("reject %s", cl.Reject)
			}
			var prev []RoundOutcome
			rescued := false
			for round := 1; round <= 7; round++ {
				in := roundInput(cl, protocol.Traits{}, protocol.Traits{}, round, prev)
				in.Views, in.RescueUsed = c.views, rescued
				in.AllowExtreme, in.MaxRounds, in.HandshakeMs = true, 6, 40000
				in.Policy.Budget.Birthday = protocol.BirthdayAggressive
				dec := p.Round(in)
				if dec.Stop != "" {
					break
				}
				checkAdmitted(t, c.name, dec, c.views, c.pair, c.maxTargets)
				o := outcomeOf(round, dec, RCNoContact)
				if round == 1 {
					// The ladder's A side heard its peer once: on every
					// address kind it may have come from. (A pdf_x_rnd
					// family whose random B side heard needs no rescue.)
					seer := roleIndex(cl.SideA)
					o.Class = RCOneWay
					o.SeenFrom[seer] = heardFrom(c.views[1-seer])
				}
				rescued = rescued || dec.Rescue
				prev = append(prev, o)
				if dec.Final {
					break
				}
			}
			if !rescued {
				t.Fatal("no rescue round was planned")
			}
		})
	}
}

// heardFrom is what a side may report as seen_from about peer v: a new port
// on each of the peer's addresses, and an address the peer never reported.
func heardFrom(v protocol.PeerView) []netip.AddrPort {
	out := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.200:9999")}
	for _, fv := range v.Families {
		for _, e := range fv.Endpoints {
			out = append(out, netip.AddrPortFrom(e.Addr.Addr(), e.Addr.Port()+7))
		}
	}
	return out[:min(len(out), 8)]
}

// TestUnverifiedFamilyDirectOnly: an unverified family
// aims Direct stages at the peer's self-reported global addresses — the view
// is not rewritten into server-observed endpoints — at most four per side
// and round, eight packets each at most, on one socket, in a light round,
// while the verified family runs its own ladder. Its traits never start a
// predict, random or sandwich, even when they claim a sequential NAT.
func TestUnverifiedFamilyDirectOnly(t *testing.T) {
	u4, u6 := protocol.FamilyUDP4, protocol.FamilyUDP6
	views := [2]protocol.PeerView{
		{Families: []protocol.FamilyView{selfV6(1, pdfTraits(u6)), siblingView(openTraits(u4)).Families[0]}},
		{Families: []protocol.FamilyView{selfV6(2, seqTraits(u6)), siblingView(pdfTraits(u4)).Families[0]}},
	}
	pair := protocol.PairFacts{SharedFamilies: []protocol.Family{u6, u4}, Unverified: map[protocol.Family]bool{u6: true}}
	var p DefaultPlanner
	cl := p.Classify(ClassifyInput{Initiator: views[0], Responder: views[1], Pair: pair, Policy: protocol.Policy{Budget: protocol.DefaultBudget()}})
	if !slices.Equal(cl.Families, []protocol.Family{u6, u4}) || cl.PairClass != PairPDFSeq || !cl.fams[0].Unverified ||
		cl.fams[1].Unverified || cl.fams[0].MaxTargets != maxUnverifiedTargets {
		t.Fatalf("classification %s %+v", cl.PairClass, cl.fams)
	}
	var prev []RoundOutcome
	sent := 0
	for round := 1; round <= 6; round++ {
		in := roundInput(cl, protocol.Traits{}, protocol.Traits{}, round, prev)
		in.Views, in.SandwichOK = views, true
		in.AllowExtreme, in.MaxRounds, in.HandshakeMs = true, 6, 40000
		dec := p.Round(in)
		if dec.Stop != "" {
			break
		}
		if fr := dec.Families[0]; fr.Variant != VInvalid && fr.Budget != protocol.BudgetLight {
			t.Fatalf("round %d: the unverified family runs %s", round, fr.Budget)
		}
		if sandwichOf(dec) != [2]bool{} {
			t.Fatalf("round %d: sandwich %v from self-reported traits", round, sandwichOf(dec))
		}
		for r := range 2 {
			v6 := dec.Sides[r][0]
			peer, _ := findFamily(views[1-r], u6)
			if v6.Family != u6 || v6.Sockets != 1 {
				t.Fatalf("round %d side %d: %s", round, r, describe(v6))
			}
			for _, st := range v6.Stages {
				switch st.Kind {
				case protocol.StageReplyOnly:
					continue
				case protocol.StageDirect:
				default:
					t.Fatalf("round %d side %d: %s stage", round, r, st.Kind)
				}
				sent++
				want := []netip.AddrPort{peer.Endpoints[0].Addr, peer.Endpoints[1].Addr} // the two global ones, not the ULA
				if !slices.Equal(st.Targets, want) || st.Repeats > maxUnverifiedRepeats {
					t.Fatalf("round %d side %d: stage %+v, want the peer's self-reported global addresses %v", round, r, st, want)
				}
			}
		}
		checkAdmitted(t, "unverified_v6", dec, views, pair, maxUnverifiedTargets)
		prev = append(prev, outcomeOf(round, dec, RCNoContact))
		if dec.Final {
			break
		}
	}
	if sent == 0 {
		t.Fatal("the unverified family never sent")
	}
}

// TestRelayOnlyTargets: with every family unverified a side aims at
// up to 16 targets — all on the first four global IPs the peer reported, the
// ones its client admits; with one verified family left, at most four.
func TestRelayOnlyTargets(t *testing.T) {
	c := admissionCaseNamed(t, "relay_only/easy")
	var p DefaultPlanner
	cl := p.Classify(ClassifyInput{Initiator: c.views[0], Responder: c.views[1], Pair: c.pair, Policy: protocol.Policy{Budget: protocol.DefaultBudget()}})
	if cl.fams[0].MaxTargets != maxRelayOnlyTargets || cl.fams[1].MaxTargets != maxRelayOnlyTargets {
		t.Fatalf("classification %+v", cl.fams)
	}
	in := roundInput(cl, protocol.Traits{}, protocol.Traits{}, 1, nil)
	in.Views = c.views
	dec := p.Round(in)
	v4 := dec.Sides[0][1]
	var targets []netip.AddrPort
	ips := map[netip.Addr]bool{}
	for _, st := range v4.Stages {
		targets = append(targets, st.Targets...)
		for _, a := range st.Targets {
			ips[a.Addr()] = true
		}
	}
	// Four IPs of two ports each are admitted; the fifth IP is not.
	if len(targets) != 8 || len(ips) != 4 || ips[netip.MustParseAddr("198.51.102.14")] || int(v4.MaxPackets) > maxUnverifiedRepeats*len(targets) {
		t.Fatalf("relay-only side %s: %d targets on %v", describe(v4), len(targets), ips)
	}
	checkAdmitted(t, c.name, dec, c.views, c.pair, maxRelayOnlyTargets)

	// The limits themselves, on a view with more admissible endpoints.
	var fv protocol.FamilyView
	for ip := range 4 {
		for port := range 5 {
			fv.Endpoints = append(fv.Endpoints, protocol.Endpoint{Source: protocol.EndpointSTUN,
				Addr: netip.MustParseAddrPort(fmt.Sprintf("198.51.100.%d:%d", 10+ip, 42000+port))})
		}
	}
	for _, limit := range []int{maxRelayOnlyTargets, maxUnverifiedTargets} {
		pa := peerAddrsOf(familyPlan{Unverified: true, MaxTargets: limit}, fv)
		if len(pa.direct) != limit || len(pa.public) != 4 || pa.sprayIP.IsValid() {
			t.Fatalf("limit %d: %+v", limit, pa)
		}
	}
	c.pair.Unverified = map[protocol.Family]bool{protocol.FamilyUDP4: true}
	cl = p.Classify(ClassifyInput{Initiator: c.views[0], Responder: c.views[1], Pair: c.pair, Policy: protocol.Policy{Budget: protocol.DefaultBudget()}})
	if cl.fams[1].MaxTargets != maxUnverifiedTargets || cl.fams[0].Unverified {
		t.Fatalf("one family unverified: %+v", cl.fams)
	}
}

// TestSameLANStage: on a shared LAN every round gives each
// side a Direct stage of its own toward the peer's LAN endpoints — first, at
// most four targets on the four LAN IPs the client keeps, two packets each,
// from the primary socket even when the round's public Direct uses many
// sockets — and the stage is counted exactly in MaxPackets.
func TestSameLANStage(t *testing.T) {
	c := admissionCaseNamed(t, "same_lan/pdf_x_seq")
	var p DefaultPlanner
	cl := p.Classify(ClassifyInput{Initiator: c.views[0], Responder: c.views[1], Pair: c.pair, Policy: protocol.Policy{Budget: protocol.DefaultBudget()}})
	var prev []RoundOutcome
	multi := false
	for round := 1; round <= 6; round++ {
		in := roundInput(cl, protocol.Traits{}, protocol.Traits{}, round, prev)
		in.Views = c.views
		in.AllowExtreme, in.MaxRounds, in.HandshakeMs = true, 6, 40000
		dec := p.Round(in)
		if dec.Stop != "" {
			break
		}
		for r := range 2 {
			fs := dec.Sides[r][0]
			lan := fs.Stages[0]
			want := []netip.AddrPort{
				netip.MustParseAddrPort("192.168.1.10:40000"), netip.MustParseAddrPort("192.168.1.10:40001"),
				netip.MustParseAddrPort("192.168.1.11:40000"), netip.MustParseAddrPort("192.168.1.12:40000"),
			}
			if lan.Kind != protocol.StageDirect || !slices.Equal(lan.Targets, want) || lan.Repeats != lanRepeats || lan.TTL != 0 || lan.AtMs != 0 {
				t.Fatalf("round %d side %d: LAN stage %+v", round, r, lan)
			}
			multi = multi || fs.Sockets > 1
		}
		checkAdmitted(t, c.name, dec, c.views, c.pair, 0)
		prev = append(prev, outcomeOf(round, dec, RCNoContact))
		if dec.Final {
			break
		}
	}
	if !multi {
		t.Fatal("no multi-socket round: the LAN stage's single socket went untested")
	}

	// Two LANs behind one upstream NAT: no LAN target, and the upstream-LAN
	// candidate is left to peer_targets.
	up := admissionCaseNamed(t, "upstream/pdf_x_seq")
	cl = p.Classify(ClassifyInput{Initiator: up.views[0], Responder: up.views[1], Pair: up.pair, Policy: protocol.Policy{Budget: protocol.DefaultBudget()}})
	in := roundInput(cl, protocol.Traits{}, protocol.Traits{}, 1, nil)
	in.Views = up.views
	dec := p.Round(in)
	for r := range 2 {
		for _, st := range dec.Sides[r][0].Stages {
			for _, a := range st.Targets {
				if privateAddr(a.Addr()) {
					t.Fatalf("side %d aims at %v on another LAN", r, a)
				}
			}
		}
	}
}

// TestLANStageBudget: a short grant trims the LAN stage last-target first,
// then to one repeat; it never takes more than the grant.
func TestLANStageBudget(t *testing.T) {
	four := []netip.AddrPort{
		netip.MustParseAddrPort("192.168.1.1:1000"), netip.MustParseAddrPort("192.168.1.2:1000"),
		netip.MustParseAddrPort("192.168.1.3:1000"), netip.MustParseAddrPort("192.168.1.4:1000"),
	}
	st := lanStage(append(four, netip.MustParseAddrPort("192.168.1.5:1000")), nil)
	if st == nil {
		t.Fatal("no LAN stage")
	}
	if len(st.Targets) != maxLANTargets || lanPackets(st) != 8 || lanStage(nil, nil) != nil {
		t.Fatalf("stage %+v", st)
	}
	// Overlay targets follow the LAN ones, at most two.
	ovl := []netip.AddrPort{netip.MustParseAddrPort("100.64.1.1:1000"), netip.MustParseAddrPort("100.64.1.2:1000"),
		netip.MustParseAddrPort("100.64.1.3:1000")}
	both := lanStage(four[:1], ovl)
	if both == nil {
		t.Fatal("no LAN and overlay stage")
	}
	if len(both.Targets) != 1+maxOverlayTargets || both.Targets[0] != four[0] {
		t.Fatalf("LAN and overlay stage %+v", both)
	}
	for _, c := range []struct{ budget, targets, repeats int }{{9, 4, 2}, {8, 4, 2}, {7, 3, 2}, {2, 1, 2}, {1, 1, 1}} {
		got := fitLAN(st, c.budget)
		if got == nil {
			t.Fatalf("budget %d: no stage", c.budget)
		}
		if len(got.Targets) != c.targets || int(got.Repeats) != c.repeats || lanPackets(got) > c.budget {
			t.Errorf("budget %d: %d targets × %d", c.budget, len(got.Targets), got.Repeats)
		}
	}
	if fitLAN(st, 0) != nil || len(st.Targets) != 4 {
		t.Fatal("a zero grant keeps a LAN stage, or fitLAN changed its input")
	}
}

// TestVariantTableReadOnly: the variant table is built once; a
// decision never aliases it, so a caller that edits a plan cannot change
// the next one.
func TestVariantTableReadOnly(t *testing.T) {
	f := protocol.FamilyUDP4
	var p DefaultPlanner
	cl := p.Classify(classifyInput(pdfTraits(f), seqTraits(f)))
	in := roundInput(cl, pdfTraits(f), seqTraits(f), 1, nil)
	before := p.Round(in)
	for r := range 2 {
		for i := range before.Sides[r] {
			for j := range before.Sides[r][i].Stages {
				st := &before.Sides[r][i].Stages[j]
				for k := range st.Steps {
					st.Steps[k] = 99
				}
				for k := range st.Targets {
					st.Targets[k] = netip.AddrPort{}
				}
			}
		}
	}
	after := p.Round(in)
	fresh := p.Round(roundInput(cl, pdfTraits(f), seqTraits(f), 1, nil))
	if fmt.Sprint(after.Sides) != fmt.Sprint(fresh.Sides) {
		t.Fatal("editing a decision changed the next one")
	}
	if vr, ok := variantOf(vPDFSeq1); !ok || vr.a.stages[1].steps != nil {
		t.Fatalf("template %+v", vr.a.stages)
	}
	if allocs := testing.AllocsPerRun(20, func() { variantOf(vPDFSeq4) }); allocs != 0 {
		t.Fatalf("variantOf allocates %v", allocs)
	}
}
