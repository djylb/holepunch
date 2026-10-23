package e2e

import (
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/djylb/holepunch/internal/wiretype"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

// class is an expectation class of a cell.
type class uint8

const (
	classMust class = iota + 1
	classShould
	classModel
	classFail
	classDegraded
)

func (c class) String() string {
	switch c {
	case classMust:
		return "must"
	case classShould:
		return "should"
	case classModel:
		return "model"
	case classFail:
		return "fail"
	case classDegraded:
		return "degraded"
	}
	return "?"
}

// cell is one cell of the e2e matrix.
type cell struct {
	world   func(*worldConfig)
	build   func(*world) [2]*side
	session func(*sessionSpec, *world, [2]*side)
	// check adds per-run assertions (the shared-network cells).
	check func(*cellRun) error
	name  string // group/initiator-responder
	group string
	// want is the Reason of both sides of a fail cell, fail how it fails
	// and failBound its time bound beyond probe_timeout (failEarly) or
	// handshake_timeout (failLadder).
	want protocol.Reason
	// truth describes how a deliberately misclassified NAT really behaves, for
	// the report.
	truth string
	// minPass overrides the pass-rate threshold (should: 19/20 PDF×SEQ,
	// 18/20 SEQ×SEQ, 16/20 noise λ=5). Zero takes the class default.
	minPass   float64
	failBound time.Duration
	// maxMedianRound bounds the median first successful round (PDF×SEQ:
	// 2).
	maxMedianRound int
	// extraTime is added to the time bound of the class: the latency a
	// cell injects beyond the suite's reference links (slow control links).
	extraTime time.Duration
	// skewP90 bounds the p90 of the first-send skew (slow control links);
	// 0 means no bound.
	skewP90 time.Duration
	// modelFactor is the share of the birthday model the success rate must
	// not fall significantly below: 0.8 by default, 1 where the
	// cell must reach the model.
	modelFactor float64
	// hard marks the endpoint-dependent sides whose sockets the birthday
	// model counts (model class).
	hard  [2]bool
	class class
	// base is the class the thresholds come from: the class itself, or the
	// base cell's class for degraded cells.
	base class
	// reportOnly reports the success rate, the p95 time and the first
	// successful round without gating on them (noise λ=20; the misclassified
	// cells). The per-run invariants
	// — budgets, rates, ports, shape, resources — still hold.
	reportOnly bool
	fail       failKind
	// plannedModel computes the birthday model from each round's grants —
	// what the round would send if it ran its whole window — instead of
	// what was actually sent, which stops at the first contact: the
	// Background cells are gated against the slow birthday's planned
	// success.
	plannedModel bool
}

// failKind is how a fail cell ends.
type failKind uint8

const (
	// failEarly: before any punch packet (no common family, a blackholed
	// probe, UDP blocked), within probe_timeout + failBound of Punch.
	failEarly failKind = iota
	// failLadder: once the ladder ran (a silent peer), within
	// handshake_timeout + failBound of the first go and the session
	// budget.
	failLadder
	// failVerdict: the hopeless SYMRND × SYMRND pair, decided by what
	// natprobe measured (checkVerdict).
	failVerdict
)

// passRate is the cell's minimum success rate, or -1 for none.
func (c *cell) passRate() float64 {
	if c.reportOnly {
		return -1
	}
	if c.minPass != 0 {
		return c.minPass
	}
	switch c.class {
	case classMust, classFail:
		return 1
	case classShould:
		return 19.0 / 20
	case classModel:
		return -1 // the birthday model test gates it
	case classDegraded:
		switch c.base {
		case classMust:
			return 0.95
		case classShould:
			return 0.85
		case classModel, classFail, classDegraded:
			return -1
		}
	}
	return -1
}

// confirmBound is the p95 bound of Punch on success.
func (c *cell) confirmBound() time.Duration {
	var b time.Duration
	switch c.base {
	case classMust:
		b = 1500 * time.Millisecond
	case classShould:
		b = 4 * time.Second
	default:
		return 0
	}
	if c.class == classDegraded {
		b += time.Second
	}
	return b + c.extraTime
}

// packetBound is the bound on initiated packets per side for the must and
// should classes; 0 means the model bound.
func (c *cell) packetBound() int {
	switch c.base {
	case classMust:
		return 150
	case classShould:
		return 800
	default:
		return 0
	}
}

// profile is a named NAT profile.
type profile struct {
	name string
	cfg  func() nattest.NATConfig
	hard bool // endpoint-dependent mapping with random ports
	// combo is the profile's class in the 15 combinations of profile
	// classes: OPEN (nothing filtered beyond the mapping),
	// ADF, PDF, SEQ or RND.
	combo string
}

var v4Profiles = []profile{
	{"PUB", profPUB, false, "OPEN"},
	{"PUBFW", profPUBFW, false, "PDF"},
	{"FC", profFC, false, "OPEN"},
	{"RC", profRC, false, "ADF"},
	{"PRC", profPRC, false, "PDF"},
	{"SYMSEQ", profSYMSEQ, false, "SEQ"},
	{"SYMRND", profSYMRND, true, "RND"},
}

// twoSidedBirthdayRound is the round of rnd_x_rnd's two-sided birthday.
const twoSidedBirthdayRound = 3

// v4Profile returns the IPv4 profile of a name.
func v4Profile(name string) profile {
	i := slices.IndexFunc(v4Profiles, func(p profile) bool { return p.name == name })
	return v4Profiles[i]
}

// v4Class is the class of an ordered IPv4 pair: a SYMRND side against
// SYMRND, SYMSEQ or a port-dependent filtering side (PUBFW, PRC) makes a model
// cell, a SYMSEQ side against SYMSEQ or a port-dependent filtering side a
// should cell; every other pair, with a side that filters by address only or
// not at all, is must. Cells of the other groups take the class of their
// IPv4 pair the same way: the scan, noise, dual-stack, NAT66/NPTv6, same-host
// and misclassified cells.
func v4Class(a, b string) class {
	pdf := func(x string) bool { return x == "PUBFW" || x == "PRC" }
	switch {
	case a == "SYMRND" && b == "SYMRND":
		return classModel
	case a == "SYMRND" && (pdf(b) || b == "SYMSEQ"), b == "SYMRND" && (pdf(a) || a == "SYMSEQ"):
		return classModel
	case a == "SYMSEQ" && (pdf(b) || b == "SYMSEQ"), b == "SYMSEQ" && pdf(a):
		return classShould
	}
	return classMust
}

// The slow, asymmetric control group: control links of 50 and
// 250 ms one way, UDP RTT 300 ms (15 ms per uplink, 120 ms across the core).
const (
	slowCtlFast = 50 * time.Millisecond
	slowCtlSlow = 250 * time.Millisecond
	slowUplink  = 15 * time.Millisecond
	slowCore    = 120 * time.Millisecond
)

// slowCtlExtra is the latency the slow-control cells inject beyond the
// suite's reference links (control ≤ ctlMax one way, UDP one way
// ≤ two uplinks of uplinkMax): the slower control link on each of the five
// legs before the first packet (punch_start, report, summary, ready, go),
// and the slower UDP path on each of the four UDP round trips (two probe
// exchanges, nominate/accept, ready/ack). The cell's time bound adds it to
// the base + 1 s; the "+1 s" alone is below
// the physical floor of these cells (about 2.4 s).
const slowCtlExtra = 5*(slowCtlSlow-ctlMax) + 4*2*(2*slowUplink+slowCore-2*uplinkMax)

// single builds two clients behind one NAT each.
func single(a, b func() nattest.NATConfig) func(*world) [2]*side {
	return func(w *world) [2]*side {
		return [2]*side{w.behind([]nattest.NATConfig{a()}), w.behind([]nattest.NATConfig{b()})}
	}
}

// v6only builds a client with an IPv6 address only.
func v6only(cfg nattest.NATConfig) func(*world) *side {
	return func(w *world) *side { return w.behind([]nattest.NATConfig{cfg}, netip.IPv6Unspecified()) }
}

// pair combines two side builders.
func pair(a, b func(*world) *side) func(*world) [2]*side {
	return func(w *world) [2]*side { return [2]*side{a(w), b(w)} }
}

func one(cfg func() nattest.NATConfig) func(*world) *side {
	return func(w *world) *side { return w.behind([]nattest.NATConfig{cfg()}) }
}

func v4only(cfg func() nattest.NATConfig) func(*world) *side {
	return func(w *world) *side { return w.behind([]nattest.NATConfig{cfg()}, netip.IPv4Unspecified()) }
}

func dualStack(w *worldConfig) { w.serverV6 = true }

// measure records what natprobe measured of each side (worldConfig.measure).
func measure(w *worldConfig) { w.measure = true }

// background runs a cell's sessions in Background mode.
func background(s *sessionSpec, _ *world, _ [2]*side) { s.background = true }

// cells returns the matrix: the NAT pair cells and the same-host cell.
func cells() []*cell {
	var out []*cell
	add := func(c *cell) {
		if c.base == 0 {
			c.base = c.class
		}
		out = append(out, c)
	}

	// v4: 7 × 7 ordered.
	for _, a := range v4Profiles {
		for _, b := range v4Profiles {
			c := &cell{name: "v4/" + a.name + "-" + b.name, group: "v4", class: v4Class(a.name, b.name),
				hard: [2]bool{a.hard, b.hard}, build: single(a.cfg, b.cfg)}
			switch {
			case a.name == "SYMSEQ" && b.name == "SYMSEQ":
				c.minPass = 18.0 / 20
			case c.class == classShould:
				c.maxMedianRound = 2
			case a.name == "SYMRND" && b.name == "SYMRND":
				// Extreme and the aggressive tier, handshake 30 s, and rounds
				// enough to reach the two-sided birthday (the third rung of
				// rnd_x_rnd); with the suite's two rounds the summary-time
				// verdict would end the session, as in neg/symrnd-default.
				c.world = func(wc *worldConfig) {
					wc.extreme = true
					b := protocol.CeilingBudget()
					wc.policy = &protocol.Policy{Budget: b}
					wc.timeouts = e2eTimeouts()
					wc.timeouts.HandshakeTimeoutMs = 30000
					wc.timeouts.MaxRounds = twoSidedBirthdayRound
				}
			}
			add(c)
		}
	}

	// v6: PUB6/PUBFW6 ordered, NAT66(APDM) × PUBFW6, NPTv6 × PRC (NAT66).
	pub6 := v6only(withV6(profPUB(), nattest.Open))
	pubfw6 := v6only(withV6(profPUBFW(), nattest.APDF))
	for _, a := range []struct {
		n string
		f func(*world) *side
	}{{"PUB6", pub6}, {"PUBFW6", pubfw6}} {
		for _, b := range []struct {
			n string
			f func(*world) *side
		}{{"PUB6", pub6}, {"PUBFW6", pubfw6}} {
			add(&cell{name: "v6/" + a.n + "-" + b.n, group: "v6", class: classMust, world: dualStack, build: pair(a.f, b.f)})
		}
	}
	nat66 := profSYMSEQ()
	nat66.IPv6 = &nattest.IPv6Config{Mode: nattest.NAT66}
	add(&cell{name: "v6/NAT66SEQ-PUBFW6", group: "v6", class: classShould, world: dualStack, build: pair(v6only(nat66), pubfw6)})
	npt := profPUBFW()
	npt.Mapping = nattest.EIM
	npt.IPv6 = &nattest.IPv6Config{Mode: nattest.NPTv6, Firewall: nattest.APDF}
	prc66 := profPRC()
	prc66.IPv6 = &nattest.IPv6Config{Mode: nattest.NAT66}
	add(&cell{name: "v6/NPTV6-PRC66", group: "v6", class: classMust, world: dualStack, build: pair(v6only(npt), v6only(prc66))})

	// Dual stack: an IPv4 profile with a firewalled IPv6 /64 on each side.
	ds := func(v4 func() nattest.NATConfig, fw nattest.Filtering) func(*world) *side {
		return func(w *world) *side { return w.behind([]nattest.NATConfig{withV6(v4(), fw)}) }
	}
	for _, d := range []struct {
		n    string
		a, b func(*world) *side
	}{
		{"PRC+FW6-SYMRND+FW6", ds(profPRC, nattest.APDF), ds(profSYMRND, nattest.APDF)},
		{"SYMRND+FW6-PRC+FW6", ds(profSYMRND, nattest.APDF), ds(profPRC, nattest.APDF)},
		{"PRC+FW6-PRC+FW6", ds(profPRC, nattest.APDF), ds(profPRC, nattest.APDF)},
		{"SYMRND+FW6-SYMRND+FW6", ds(profSYMRND, nattest.APDF), ds(profSYMRND, nattest.APDF)},
		{"FC+OPEN6-SYMSEQ+FW6", ds(profFC, nattest.Open), ds(profSYMSEQ, nattest.APDF)},
		{"SYMSEQ+FW6-PRC+OPEN6", ds(profSYMSEQ, nattest.APDF), ds(profPRC, nattest.Open)},
	} {
		add(&cell{name: "dual/" + d.n, group: "dual", class: classMust, world: dualStack, build: pair(d.a, d.b)})
	}

	// CGNAT: (outer, inner) × peer.
	cg := func(outer, inner func() nattest.NATConfig) func(*world) *side {
		return func(w *world) *side {
			c := nattest.CGNAT(outer(), inner())
			return w.behind([]nattest.NATConfig{c[0], c[1]})
		}
	}
	add(&cell{name: "cgnat/SYMSEQ+PRC-PRC", group: "cgnat", class: classDegraded, base: classShould, build: pair(cg(profSYMSEQ, profPRC), one(profPRC))})
	add(&cell{name: "cgnat/SYMSEQ+FC-FC", group: "cgnat", class: classDegraded, base: classMust, build: pair(cg(profSYMSEQ, profFC), one(profFC))})
	add(&cell{name: "cgnat/SYMRND+FC-PRC", group: "cgnat", class: classDegraded, base: classModel, hard: [2]bool{true, false},
		build: pair(cg(profSYMRND, profFC), one(profPRC))})
	add(&cell{name: "cgnat/PRC+PRC-SYMSEQ", group: "cgnat", class: classDegraded, base: classShould, build: pair(cg(profPRC, profPRC), one(profSYMSEQ))})

	// Several exits and address-dependent mapping.
	add(&cell{name: "multi/FCX2-PRC", group: "multi", class: classDegraded, base: classMust, build: func(w *world) [2]*side {
		c := profFC()
		c.ExternalIPs, c.ExitPolicy = w.explicitIPs(2), nattest.PerSourcePort
		return [2]*side{w.behind([]nattest.NATConfig{c}), w.behind([]nattest.NATConfig{profPRC()})}
	}})
	// natprobe observes from one server IP and cannot tell this NAT from an
	// endpoint-independent one: it is misclassified by construction,
	// and the cell records what natprobe measured.
	add(&cell{name: "multi/ADMRND-PRC", group: "multi", class: classDegraded, base: classModel, hard: [2]bool{true, false},
		world: func(wc *worldConfig) { wc.measure = true }, build: single(profADMRND, profPRC),
		truth: "ADMRND: a random port per destination IP, which one server IP cannot reveal"})
	add(&cell{name: "multi/SYMSEQRR-FC", group: "multi", class: classDegraded, base: classMust, build: func(w *world) [2]*side {
		c := profSYMSEQ()
		c.ExternalIPs, c.ExitPolicy = w.explicitIPs(2), nattest.RoundRobin
		return [2]*side{w.behind([]nattest.NATConfig{c}), w.behind([]nattest.NATConfig{profFC()})}
	}})

	// Hairpin: two hosts on one LAN behind one NAT, same /24.
	for _, hp := range []bool{false, true} {
		add(&cell{name: fmt.Sprintf("hairpin/PRC-hairpin-%v", hp), group: "hairpin", class: classMust, build: func(w *world) [2]*side {
			c := profPRC()
			c.Hairpin = hp
			a := w.behind([]nattest.NATConfig{c})
			return [2]*side{a, w.on(a.nats)}
		}, check: checkSameLAN})
	}

	// Impairment and slow, asymmetric control links over six base pairs.
	impairBase := []struct {
		a, b profile
		base class
	}{
		{v4Profiles[2], v4Profiles[2], classMust},   // FC × FC
		{v4Profiles[4], v4Profiles[4], classMust},   // PRC × PRC
		{v4Profiles[2], v4Profiles[5], classMust},   // FC × SYMSEQ
		{v4Profiles[4], v4Profiles[5], classShould}, // PRC × SYMSEQ
		{v4Profiles[5], v4Profiles[5], classShould}, // SYMSEQ × SYMSEQ
		{v4Profiles[4], v4Profiles[6], classModel},  // PRC × SYMRND
	}
	for _, p := range impairBase {
		add(&cell{name: "impair/" + p.a.name + "-" + p.b.name, group: "impair", class: classDegraded, base: p.base,
			hard: [2]bool{p.a.hard, p.b.hard}, build: single(p.a.cfg, p.b.cfg),
			world: func(wc *worldConfig) {
				wc.coreLink = nattest.LinkConfig{Loss: 0.10, Jitter: 20 * time.Millisecond, Delay: 25 * time.Millisecond}
			}})
	}
	for _, p := range impairBase {
		add(&cell{name: "slowctl/" + p.a.name + "-" + p.b.name, group: "slowctl", class: classDegraded, base: p.base,
			hard: [2]bool{p.a.hard, p.b.hard},
			build: func(w *world) [2]*side {
				a, b := p.a.cfg(), p.b.cfg()
				a.Uplink = nattest.LinkConfig{Delay: slowUplink}
				b.Uplink = a.Uplink
				return [2]*side{w.behind([]nattest.NATConfig{a}), w.behind([]nattest.NATConfig{b})}
			},
			world: func(wc *worldConfig) { wc.coreLink = nattest.LinkConfig{Delay: slowCore} },
			session: func(s *sessionSpec, _ *world, _ [2]*side) {
				s.ctlDelay = [2]time.Duration{slowCtlFast, slowCtlSlow}
			},
			skewP90: 30 * time.Millisecond, extraTime: slowCtlExtra})
	}

	// Scan detection on both NATs (default thresholds), seven
	// pairs that stay below the heavy class. Below the thresholds the
	// defence changes nothing, so a scan cell keeps its pair's class.
	for _, p := range [][2]profile{
		{v4Profiles[2], v4Profiles[2]}, {v4Profiles[4], v4Profiles[4]}, {v4Profiles[3], v4Profiles[4]},
		{v4Profiles[1], v4Profiles[4]}, {v4Profiles[2], v4Profiles[5]}, {v4Profiles[4], v4Profiles[5]},
		{v4Profiles[3], v4Profiles[6]},
	} {
		scan := func(f func() nattest.NATConfig) func() nattest.NATConfig {
			return func() nattest.NATConfig {
				c := f()
				c.ScanDefense = &nattest.ScanDefense{}
				return c
			}
		}
		add(&cell{name: "scan/" + p[0].name + "-" + p[1].name, group: "scan", class: v4Class(p[0].name, p[1].name),
			build: single(scan(p[0].cfg), scan(p[1].cfg))})
	}

	// Port noise.
	n5 := func() nattest.NATConfig { return profSYMSEQNoise(5) }
	n20 := func() nattest.NATConfig { return profSYMSEQNoise(20) }
	add(&cell{name: "noise/PRC-SYMSEQ~5", group: "noise", class: classShould, minPass: 16.0 / 20, build: single(profPRC, n5)})
	add(&cell{name: "noise/PRC-SYMSEQ~20", group: "noise", class: classShould, reportOnly: true, build: single(profPRC, n20)})
	add(&cell{name: "noise/SYMSEQ~5-SYMSEQ~5", group: "noise", class: classShould, minPass: 16.0 / 20, build: single(n5, n5)})
	add(&cell{name: "noise/PUBFW-SYMSEQ~5", group: "noise", class: classShould, minPass: 16.0 / 20, build: single(profPUBFW, n5)})
	// Heavier noise on both sides of a paired SEQ×SEQ: the anchor refresh
	// before a round re-reads where both allocators are; λ=20 is gated at
	// 15/20, λ=50 reported only.
	n50 := func() nattest.NATConfig { return profSYMSEQNoise(50) }
	add(&cell{name: "noise/SYMSEQ~20-SYMSEQ~20", group: "noise", class: classShould, minPass: 15.0 / 20, build: single(n20, n20)})
	add(&cell{name: "noise/SYMSEQ~50-SYMSEQ~50", group: "noise", class: classShould, reportOnly: true, build: single(n50, n50)})

	// Allocator variants beyond the 7×7 profiles: a
	// sequential NAT that allocates downwards, against a PDF side
	// and paired with an upward SEQ side. Their class is that of the pair
	// with an upward SEQ.
	add(&cell{name: "alloc/PRC-SYMSEQ-1", group: "alloc", class: classShould, maxMedianRound: 2, world: measure,
		build: single(profPRC, profSYMSEQDown)})
	add(&cell{name: "alloc/SYMSEQ-1-SYMSEQ", group: "alloc", class: classShould, minPass: 18.0 / 20, world: measure,
		build: single(profSYMSEQDown, profSYMSEQ)})
	// A NAT whose fresh socket keeps its local port for its first mapping: its
	// random later mappings would make it a birthday pair, but natprobe sees
	// the kept port on both probing sockets and the plan binds fresh sockets at
	// drawn ports the peer aims at exactly. Like PDF×SEQ, the pair is predicted
	// rather than observed, hence should.
	add(&cell{name: "alloc/PRC-PRESRND", group: "alloc", class: classShould, maxMedianRound: 2, world: measure,
		build: single(profPRC, profPRESRND)})
	add(&cell{name: "alloc/PRESRND-PRESRND", group: "alloc", class: classShould, maxMedianRound: 2, world: measure,
		build: single(profPRESRND, profPRESRND)})

	// Background mode: the PDF × RND pairs of the
	// v4 matrix with the slow birthday — 120 sockets of the RND side opened
	// 16 a second, 25 PDF-side ports a second for 41 s — gated, as model
	// cells, against the birthday model of what they actually sent (about
	// 85% in the 45 s window). The scan-defence pair proves the slow tier
	// stays below the default scan thresholds: no ban.
	for _, bp := range [][2]profile{
		{v4Profile("PRC"), v4Profile("SYMRND")}, {v4Profile("SYMRND"), v4Profile("PRC")},
		{v4Profile("PUBFW"), v4Profile("SYMRND")}, {v4Profile("SYMRND"), v4Profile("PUBFW")},
	} {
		add(&cell{name: "bg/" + bp[0].name + "-" + bp[1].name, group: "bg", class: classModel, hard: [2]bool{bp[0].hard, bp[1].hard},
			build: single(bp[0].cfg, bp[1].cfg), session: background, plannedModel: true})
	}
	scanned := func(f func() nattest.NATConfig) func() nattest.NATConfig {
		return func() nattest.NATConfig {
			c := f()
			c.ScanDefense = &nattest.ScanDefense{}
			return c
		}
	}
	for _, bp := range [][2]profile{{v4Profile("PRC"), v4Profile("SYMRND")}, {v4Profile("SYMRND"), v4Profile("PUBFW")}} {
		add(&cell{name: "bgscan/" + bp[0].name + "-" + bp[1].name, group: "bgscan", class: classModel, hard: [2]bool{bp[0].hard, bp[1].hard},
			build: single(scanned(bp[0].cfg), scanned(bp[1].cfg)), session: background, plannedModel: true})
	}

	// Deliberately misclassified: the NAT behaves
	// otherwise than natprobe measured it, and only the corrections made
	// while punching (peer_seen, sandwich, rounds, rescue) can recover.
	for _, mc := range misclassCells() {
		add(mc)
	}

	// Mapping timeout 2 s with the responder 2.5 s late.
	short := func(f func() nattest.NATConfig) func() nattest.NATConfig {
		return func() nattest.NATConfig {
			c := f()
			c.MappingTimeout = 2 * time.Second
			return c
		}
	}
	late := func(s *sessionSpec, _ *world, _ [2]*side) { s.late = 2500 * time.Millisecond }
	add(&cell{name: "maptimeout/PRC-PRC", group: "maptimeout", class: classDegraded, base: classMust, build: single(short(profPRC), short(profPRC)), session: late})
	add(&cell{name: "maptimeout/SYMSEQ-FC", group: "maptimeout", class: classDegraded, base: classMust, build: single(short(profSYMSEQ), short(profFC)), session: late})

	// Rebind: the full-cone side changes its external IP before the first go.
	add(&cell{name: "rebind/PRC-FC", group: "rebind", class: classDegraded, base: classMust, build: single(profPRC, profFC),
		session: func(s *sessionSpec, w *world, sides [2]*side) {
			s.prepare = func(r *run) {
				ready := r.taps[1].when(toServer, wiretype.PunchReady, nil)
				w.helpers.Add(1)
				go func() {
					defer w.helpers.Done()
					select {
					case <-ready:
						sides[1].nats[0].Rebind(nil)
					case <-r.ctx[1].Done():
					case <-w.quit:
					}
				}()
			}
		}})

	// Network stacks and a shared upstream NAT: two homes behind one carrier
	// NAT, with its hairpin and the home routers' port mappings on or off;
	// dual-stack clients of an IPv4-only server; an IPv4-only client of a
	// dual-stack server; two hosts on one LAN behind a carrier NAT.
	for _, ns := range []struct {
		n             string
		hairpin, pmap bool
		class         class
	}{
		{"upstream+hairpin+portmap", true, true, classMust}, {"upstream+hairpin", true, false, classMust},
		{"upstream+portmap", false, true, classMust}, {"upstream", false, false, classFail},
	} {
		c := &cell{name: "ns/" + ns.n, group: "ns", class: ns.class, build: upstreamPair(ns.hairpin, ns.pmap),
			check: checkUpstream(ns.hairpin, ns.pmap)}
		if ns.class == classFail {
			c.want, c.fail, c.failBound = protocol.ReasonCandidateTimeout, failLadder, time.Second
		}
		add(c)
	}
	add(&cell{name: "ns/v6-unverified", group: "ns", class: classMust, build: pair(ds(profPRC, nattest.APDF), ds(profPRC, nattest.APDF)), check: checkUnverifiedV6})
	add(&cell{name: "ns/v4only-client", group: "ns", class: classMust, world: dualStack, build: pair(v4only(profPRC), ds(profPRC, nattest.APDF)), check: checkV4OnlyClient})
	add(&cell{name: "ns/cgnat-same-lan", group: "ns", class: classMust, build: func(w *world) [2]*side {
		c := nattest.CGNAT(profPRC(), profFC())
		a := w.behind([]nattest.NATConfig{c[0], c[1]})
		return [2]*side{a, w.on(a.nats)}
	}, check: checkSameLAN})

	// Negative cells.
	add(&cell{name: "neg/v4only-v6only", group: "neg", class: classFail, want: protocol.ReasonNoCommonFamily,
		failBound: 500 * time.Millisecond, world: dualStack, build: pair(v4only(profPRC), pubfw6)})
	add(&cell{name: "neg/probe-blackhole", group: "neg", class: classFail, want: protocol.ReasonProbeTimeout,
		failBound: 500 * time.Millisecond, build: single(profPRC, profPRC),
		session: func(s *sessionSpec, w *world, _ [2]*side) {
			s.prepare = func(*run) { w.srvNAT.Blackhole(time.Hour) }
		}})
	add(&cell{name: "neg/udp-blocked", group: "neg", class: classFail, want: protocol.ReasonUDPBlocked,
		failBound: 500 * time.Millisecond, build: single(profPRC, profPRC),
		session: func(_ *sessionSpec, _ *world, sides [2]*side) { sides[0].host.FailWrites("", -1, nil) }})
	add(&cell{name: "neg/peer-silent", group: "neg", class: classFail, want: protocol.ReasonCandidateTimeout,
		fail: failLadder, failBound: time.Second, build: single(profPRC, profPRC),
		session: func(_ *sessionSpec, _ *world, sides [2]*side) {
			for i := range 2 {
				peer := sides[1-i].publicIPs()
				sides[i].net.dropFrom(func(from netip.AddrPort) bool {
					for _, a := range peer {
						if a == from.Addr().Unmap() {
							return true
						}
					}
					return false
				})
			}
		}})
	// The hopeless SYMRND × SYMRND pair, judged by what natprobe measured:
	// the default probe gives it six port samples per side, enough for Random
	// at High confidence and the summary-time verdict; without the second
	// socket three, Low, and the two cheap rounds run first.
	add(&cell{name: "neg/symrnd-default", group: "neg", class: classFail, want: protocol.ReasonHardSymmetricRandom,
		fail: failVerdict, failBound: time.Second, world: measure, build: single(profSYMRND, profSYMRND)})
	add(&cell{name: "neg/symrnd-low-confidence", group: "neg", class: classFail, want: protocol.ReasonHardSymmetricRandom,
		fail: failVerdict, failBound: time.Second, build: single(profSYMRND, profSYMRND),
		world: func(wc *worldConfig) { wc.measure, wc.noSecondSocket = true, true }})

	// Situations found on real networks: protocol classifiers, path-dependent
	// mappings and destination-dependent routes.
	for _, c := range append(classifierCells(), routeCells()...) {
		add(c)
	}

	// Two clients on one host.
	add(&cell{name: "samehost/PRC", group: "samehost", class: classMust, build: func(w *world) [2]*side {
		a := w.behind([]nattest.NATConfig{profPRC()})
		return [2]*side{a, sameHost(a)}
	}})
	return out
}

// explicitIPs returns n fresh public IPv4 addresses for a multi-exit NAT,
// from a block the automatic plan does not reach in a test world.
func (w *world) explicitIPs(n int) []netip.Addr {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]netip.Addr, n)
	for i := range out {
		w.nextIP++
		out[i] = netip.AddrFrom4([4]byte{198, 19, byte(w.nextIP >> 8), byte(w.nextIP)})
	}
	return out
}

// upstreamPair builds the shared-upstream cells: two homes on different LANs
// behind one carrier NAT (PortRestricted outside, FullCone home routers),
// with the carrier's hairpin on or off and the home routers' port mappings
// reported or not.
func upstreamPair(hairpin, pmap bool) func(*world) [2]*side {
	return func(w *world) [2]*side {
		c := nattest.CGNAT(profPRC(), profFC())
		c[0].Hairpin = hairpin
		c[0].Uplink = nattest.LinkConfig{Delay: w.delay(uplinkMin, uplinkMax)}
		carrier := w.n.NAT(c[0])
		var out [2]*side
		for i := range out {
			home := carrier.NAT(c[1])
			h := home.Host()
			out[i] = &side{host: h, nats: []*nattest.NAT{home, carrier}, net: newClientNet(h)}
			if pmap {
				out[i].mapper = &fakeMapper{home: home}
			}
		}
		return out
	}
}

// misclassCells are the deliberately misclassified cells: natprobe measures the
// NAT correctly at probe time, and it then behaves otherwise while the session
// punches. Their class is that of their IPv4 pair (v4Class); their success is
// reported, not gated (reportOnly), and TestAblation measures how much of it
// the punch-time corrections recover. Each records what natprobe measured.
// multi/ADMRND-PRC is the other kind: a NAT natprobe cannot classify from one
// server IP.
func misclassCells() []*cell {
	var out []*cell
	for _, l := range []struct {
		name       string
		pps        int
		afterProbe bool
	}{{"burst100", 100, true}, {"burst400", 400, true}, {"lull100", 100, false}, {"lull400", 400, false}} {
		truth := fmt.Sprintf("quiet while probed, %d ports/s for other subscribers from the summary on", l.pps)
		if !l.afterProbe {
			truth = fmt.Sprintf("%d ports/s for other subscribers while probed, quiet from the summary on", l.pps)
		}
		out = append(out, &cell{name: "misclass/PRC-SYMSEQ+" + l.name, group: "misclass", class: classShould,
			reportOnly: true, world: measure, build: single(profPRC, profSYMSEQ), truth: "SYMSEQ " + truth,
			session: func(s *sessionSpec, w *world, sides [2]*side) {
				s.prepare = func(r *run) { w.load(r, sides[1].nats[0], 1, l.pps, l.afterProbe) }
			}})
	}
	return out
}
