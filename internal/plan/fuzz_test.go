package plan

import (
	"math"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/msgframe"
	api "github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

// FuzzPortPredict exercises the predict and random stage expansion:
// whatever the seed and parameters, every emitted port is in 1..65535, is not
// sensitive or sub-1024, is unique, the count never exceeds the declared span
// or count, and no run of consecutive ports exceeds three (a hard
// constraint).
func FuzzPortPredict(f *testing.F) {
	f.Add(uint64(1), uint16(40000), int16(1), uint16(16), uint16(0), uint16(0), uint16(64), false)
	f.Add(uint64(42), uint16(2000), int16(-2), uint16(48), uint16(40000), uint16(40099), uint16(368), true)
	f.Add(uint64(7), uint16(1), int16(1), uint16(4096), uint16(0), uint16(0), uint16(4096), false)

	f.Fuzz(func(t *testing.T, seedN uint64, anchor uint16, step int16, span uint16, lo, hi, count uint16, random bool) {
		var seed [8]byte
		for i := range seed {
			seed[i] = byte(seedN >> (8 * i))
		}
		var ports []uint16
		var declared int
		if random {
			ports = ExpandRandom(lo, hi, int(count), ExpandInput{Seed: seed})
			declared = int(count)
		} else {
			ports = ExpandPredict(anchor, []int16{step}, int(span), ExpandInput{Seed: seed})
			declared = int(span)
		}
		if len(ports) > declared {
			t.Fatalf("emitted %d ports > declared %d", len(ports), declared)
		}
		seen := make(map[uint16]struct{}, len(ports))
		for _, p := range ports {
			if p < 1024 {
				t.Fatalf("sub-1024 port %d", p)
			}
			if SensitivePort(p) {
				t.Fatalf("sensitive port %d", p)
			}
			if _, dup := seen[p]; dup {
				t.Fatalf("duplicate port %d", p)
			}
			seen[p] = struct{}{}
		}
		if run := MaxConsecutiveRun(ports); run > 3 {
			t.Fatalf("consecutive run %d > 3: %v", run, ports)
		}
	})
}

// FuzzRound drives Classify and a chain of Rounds over arbitrary traits,
// endpoint sets, budgets, round classes, bind failures, punch-time samples,
// shared-network pair facts (an unverified family, a shared LAN or upstream
// NAT, with LAN endpoints and an upstream-LAN candidate in the views), the
// start the strategy memory gives the ladder (the first round's baseline) and
// anchor refreshes of one probe or two, each outcome with the mappings the
// coordinator counts: no input panics, and every decision runs under the
// clients' admission exactly as planned (checkAdmitted: MaxPackets is what the
// client schedules and at least what it sends), stays within BudgetLeft and
// encodes in the message that carries it, which the client's Normalize
// leaves unchanged.
func FuzzRound(f *testing.F) {
	f.Add(uint8(1), uint8(3), uint8(2), uint8(1), uint16(3000), uint8(0), int16(1), float32(20), uint32(3000), uint64(0x0102030405))
	f.Add(uint8(4), uint8(4), uint8(6), uint8(3), uint16(120), uint8(30), int16(-2), float32(-5), uint32(9000), uint64(0xfeedface))
	f.Add(uint8(0x22), uint8(0x13), uint8(0), uint8(0), uint16(61), uint8(1), int16(0), float32(0), uint32(0), uint64(42))
	// An unverified family; a shared LAN with four LAN endpoints; an
	// upstream NAT; an unverified family on a shared LAN.
	f.Add(uint8(0x21), uint8(0x23), uint8(2), uint8(3), uint16(3000), uint8(0), int16(1), float32(0), uint32(3000), uint64(1)<<48|0x0a)
	f.Add(uint8(1), uint8(2), uint8(6), uint8(1), uint16(3000), uint8(0), int16(1), float32(10), uint32(3000), uint64(0x1a)<<48|0x15)
	f.Add(uint8(1), uint8(3), uint8(3), uint8(6), uint16(800), uint8(0), int16(2), float32(5), uint32(3000), uint64(4)<<48|0x0e)
	f.Add(uint8(0), uint8(1), uint8(0), uint8(0), uint16(3000), uint8(0), int16(1), float32(0), uint32(0), uint64(3)<<48|0x2a)
	// A memory-promoted start; refreshes of both probes, of the first only,
	// of the second only.
	f.Add(uint8(2), uint8(2), uint8(1), uint8(1), uint16(3000), uint8(0), int16(1), float32(0), uint32(2000), uint64(1)<<32|uint64(1)<<24|uint64(5)<<26)
	f.Add(uint8(1), uint8(2), uint8(4), uint8(4), uint16(3000), uint8(0), int16(1), float32(0), uint32(2000), uint64(2)<<32|uint64(2)<<24|uint64(3)<<26)
	f.Add(uint8(2), uint8(3), uint8(2), uint8(2), uint16(3000), uint8(0), int16(-1), float32(0), uint32(900), uint64(3)<<24|uint64(1)<<40)
	// A STUN-contradicted side; an overlay on both sides; an easy pair
	// of Medium sides whose rounds find no contact (escalation).
	f.Add(uint8(0x09), uint8(1), uint8(2), uint8(1), uint16(3000), uint8(0), int16(1), float32(0), uint32(3000), uint64(0))
	f.Add(uint8(1), uint8(1), uint8(2), uint8(2), uint16(3000), uint8(0), int16(1), float32(0), uint32(3000), uint64(0x20)<<48)
	f.Add(uint8(0x11), uint8(0x11), uint8(1), uint8(1), uint16(3000), uint8(0), int16(1), float32(0), uint32(3000), uint64(0))
	// A downward sequential peer whose rate of other hosts is the largest
	// finite one a traits update can carry.
	f.Add(uint8(1), uint8(2), uint8(2), uint8(1), uint16(3000), uint8(0), int16(-1), float32(-math.MaxFloat32), uint32(9000), uint64(0))
	f.Fuzz(func(t *testing.T, ca, cb, epA, epB uint8, left uint16, bind uint8, step int16, vel float32, fireMs uint32, bits uint64) {
		if v := float64(vel); math.IsNaN(v) || math.IsInf(v, 0) { // protocol validation refuses those traits
			return
		}
		mk := func(c uint8, n int) protocol.Traits {
			fam := protocol.FamilyUDP4
			if c&0x20 != 0 {
				fam = protocol.FamilyUDP6
			}
			tr := []protocol.Traits{openTraits(fam), pdfTraits(fam), seqTraits(fam), rndTraits(fam)}[int(c)%4]
			tr.Observed = observedFor(fam, n)
			tr.PortAnchor = tr.Observed.Port()
			if c&0x10 != 0 {
				tr.MappingConf = protocol.ConfMedium
			}
			if c&0x40 != 0 {
				tr.MultiExit = true
			}
			if c&0x80 != 0 {
				tr.NoNAT = protocol.TriTrue
			}
			if c&0x08 != 0 {
				tr.PathDependent = true // a STUN server saw another port
			}
			tr.PortStep, tr.PortVelocity, tr.PortAnchorMs = step, vel, int64(fireMs/3)
			return tr
		}
		a, b := mk(ca, 1), mk(cb, 2)
		mkView := func(tr protocol.Traits, n uint8) protocol.PeerView {
			v := view(tr)
			for i := range int(n % 9) {
				ip := tr.Observed.Addr()
				if i%3 == 2 {
					ip = observedFor(tr.Family, 50+i).Addr()
				}
				src := []protocol.EndpointSource{protocol.EndpointServer, protocol.EndpointSecond, protocol.EndpointSibling}[i%3]
				v.Families[0].Endpoints = append(v.Families[0].Endpoints, protocol.Endpoint{Addr: netip.AddrPortFrom(ip, uint16(41000+i)),
					Source: src, Socket: uint8(i % 4), Verified: i%5 != 4})
			}
			if tr.PathDependent {
				v.Families[0].Endpoints = append(v.Families[0].Endpoints, protocol.Endpoint{
					Addr: netip.AddrPortFrom(tr.Observed.Addr(), tr.Observed.Port()+7), Source: protocol.EndpointSTUN})
			}
			return v
		}
		views := [2]protocol.PeerView{mkView(a, epA), mkView(b, epB)}
		var pair protocol.PairFacts
		if fl := bits >> 48; fl&0x20 != 0 { // both sides on an overlay
			pair.SharedOverlay = map[protocol.Family]bool{a.Family: true}
			for i := range views {
				ovl := netip.AddrFrom4([4]byte{100, 100, 0, byte(i + 1)})
				if a.Family == protocol.FamilyUDP6 {
					ovl = netip.MustParseAddr("fd7a:115c:a1e0::1")
				}
				views[i].Families[0].Endpoints = append(views[i].Families[0].Endpoints,
					protocol.Endpoint{Addr: netip.AddrPortFrom(ovl, uint16(42000+i)), Source: protocol.EndpointOverlay})
			}
		}
		if fl := bits >> 48; fl&7 != 0 {
			f := a.Family
			pair.Unverified = map[protocol.Family]bool{f: fl&1 != 0}
			pair.SamePublicIP = map[protocol.Family]bool{f: fl&6 != 0}
			pair.LikelySameLAN = map[protocol.Family]bool{f: fl&2 != 0}
			for i := range views {
				lan, up := "192.168.1.1", "100.64.0.1"
				if f == protocol.FamilyUDP6 {
					lan, up = "fd00::1", "fd00:64::1"
				}
				fv := &views[i].Families[0]
				for j := range fv.Endpoints {
					// The coordinator verifies nothing in an unverified family.
					fv.Endpoints[j].Verified = fv.Endpoints[j].Verified && fl&1 == 0
				}
				for j := range int(fl>>3&3) + 1 {
					fv.Endpoints = append(fv.Endpoints, protocol.Endpoint{Source: protocol.EndpointLAN,
						Addr: netip.AddrPortFrom(netip.MustParseAddr(lan).Next(), uint16(40000+10*i+j))})
				}
				fv.Endpoints = append(fv.Endpoints, protocol.Endpoint{Source: protocol.EndpointPortmap,
					Addr: netip.AddrPortFrom(netip.MustParseAddr(up), uint16(41000+i))})
			}
		}
		var p DefaultPlanner
		ci := classifyInput(a, b)
		ci.Initiator, ci.Responder, ci.Pair = views[0], views[1], pair
		cl := p.Classify(ci)
		if cl.Reject != "" {
			return
		}
		start := int(bits>>32&7) % len(cl.Ladder) // where the strategy memory starts the primary ladder
		order := append(slices.Clone(cl.Ladder[start:]), cl.Ladder[:start]...)
		var prev []api.RoundOutcome
		ledger := mappingLedger{}
		rescueUsed := false
		for round := 1; round <= 6; round++ {
			in := classified(roundInput(cl, a, b, round, prev), ci)
			in.Views, in.RescueUsed = views, rescueUsed
			in.Order, in.MemoryPromoted = order, round == 1 && start > 0
			in.BudgetLeft = [2]int{int(left), int(left>>1) + 60}
			in.Evidence.BindFailed = [2]uint16{uint16(bind & 0x3f), uint16(bind >> 6)}
			in.AllowExtreme, in.MaxRounds, in.HandshakeMs = bits&1 != 0, 6, 40000
			in.Policy.Budget.Birthday = []protocol.BirthdayTier{protocol.BirthdayOff, protocol.BirthdayConservative, protocol.BirthdayBalanced, protocol.BirthdayAggressive}[bits>>1&3]
			in.FireAt = time.Duration(fireMs) * time.Millisecond
			in.Mappings[1] = []api.MappingSample{{Addr: netip.AddrPortFrom(b.Observed.Addr(), uint16(bits>>8)), At: time.Duration(fireMs/2) * time.Millisecond,
				Round: round - 1}}
			if mode := bits >> 24 & 3; mode != 0 { // 1: both probes came, 2: the first only, 3: the second only
				for r, tr := range []protocol.Traits{a, b} {
					ar := api.AnchorRefresh{Family: tr.Family}
					port := tr.Observed.Port() + uint16(bits>>26&0x3f)
					if mode != 3 {
						ar.First, ar.FirstAt = netip.AddrPortFrom(tr.Observed.Addr(), port), in.FireAt-150*time.Millisecond
					}
					if mode != 2 {
						ar.Second, ar.SecondAt = netip.AddrPortFrom(tr.Observed.Addr(), port+uint16(bits>>40&7)), in.FireAt-90*time.Millisecond
					}
					in.Refresh[r] = []api.AnchorRefresh{ar}
				}
			}
			dec := p.Round(in)
			if dec.Stop != "" {
				return
			}
			checkAdmitted(t, "fuzz", dec, views, pair, protocol.MaxRelayOnlyTargets)
			for r := range 2 {
				total := 0
				for _, fs := range dec.Sides[r] {
					total += int(fs.MaxPackets)
				}
				if total > in.BudgetLeft[r] {
					t.Fatalf("round %d role %d: %d packets > BudgetLeft %d", round, r, total, in.BudgetLeft[r])
				}
				rp := protocol.RoundPlan{Round: uint8(round), Variant: dec.VariantName, Budget: dec.Budget, WindowMs: uint16(dec.Window / time.Millisecond),
					Seed: 1, Rescue: dec.Rescue, Sides: dec.Sides[r]}
				msg, clamped := carrier(rp)
				if _, err := msgframe.Encode(msg); err != nil {
					t.Fatalf("round %d role %d: %v", round, r, err)
				}
				if clamped {
					t.Fatalf("round %d role %d: the client's Normalize clamps %+v", round, r, rp.Sides)
				}
			}
			class := []api.RoundClass{api.RoundNoContact, api.RoundConfirmLost, api.RoundOneWay, api.RoundBlocked}[bits>>(3+2*uint(round))&3]
			o := ledger.outcome(round, dec, class)
			for i := range o.Families {
				o.Families[i].NoContact = class == api.RoundNoContact // two in a row escalate an easy family
			}
			if class == api.RoundOneWay {
				seer := round % 2
				if bits>>30&1 == 1 {
					seer = 1 // the same side hears every time: two make a PDF×RND pair
				}
				o.SeenFrom[seer] = []netip.AddrPort{views[1-seer].Families[0].Traits.Observed}
				for i := range o.Families {
					o.Families[i].Heard[seer] = true
				}
			}
			rescueUsed = rescueUsed || dec.Rescue
			prev = append(prev, o)
			if dec.Final {
				return
			}
		}
	})
}
