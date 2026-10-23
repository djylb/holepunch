package coord

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/djylb/holepunch/coord/internal/simclient"
	engine "github.com/djylb/holepunch/internal/plan"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

// evilPlanner returns plans far beyond every limit.
type evilPlanner struct {
	round func(in plan.RoundInput) plan.RoundDecision
}

func (evilPlanner) Classify(_ plan.ClassifyInput) plan.Classification {
	return plan.Classification{Families: []protocol.Family{protocol.FamilyUDP4}, SideA: protocol.RoleInitiator,
		Ladder: []plan.VariantID{1, 2}, PairClass: "Not A Name"}
}

func (e evilPlanner) Round(in plan.RoundInput) plan.RoundDecision {
	if e.round != nil {
		return e.round(in)
	}
	side := func(target netip.AddrPort) []protocol.FamilySide {
		var stages []protocol.Stage
		stages = append(stages,
			protocol.Stage{Kind: protocol.StageDirect, Targets: []netip.AddrPort{target, mustAP("8.8.8.8:53"),
				mustAP("192.168.5.5:1000"), mustAP("0.0.0.0:1"), mustAP("224.0.0.1:5")}, Repeats: 50, TTL: 1},
			protocol.Stage{Kind: protocol.StagePredict, IP: target.Addr(), Anchor: 1000, Steps: []int16{1, 2, 3, 4}, Span: 9000},
			protocol.Stage{Kind: protocol.StageRandom, IP: netip.MustParseAddr("8.8.8.8"), Count: 9000},
			protocol.Stage{Kind: "teleport"},
		)
		for range 10 {
			stages = append(stages, protocol.Stage{Kind: protocol.StageDirect, Targets: []netip.AddrPort{target}})
		}
		return []protocol.FamilySide{
			{Family: protocol.FamilyUDP4, Role: protocol.SideSender, SendDelayMs: 9000, Sockets: 1000, MaxPackets: 100000,
				MaxPPS: 10000, MaxNewPerSec: 5000, MaxDistinctPorts: 9999, Sandwich: true, Stages: stages},
			{Family: protocol.FamilyUDP6, Role: protocol.SideBoth, Sockets: 1, MaxPackets: 10,
				Stages: []protocol.Stage{{Kind: protocol.StageDirect, Targets: []netip.AddrPort{mustAP("[2001:db8::1]:1")}}}},
			{Family: protocol.FamilyUDP4, Role: "boss", Sockets: 1},
		}
	}
	return plan.RoundDecision{
		Variant: 1, VariantName: "BAD NAME", Budget: protocol.BudgetExtreme, Window: time.Hour,
		Rescue: true,
		Sides:  [2][]protocol.FamilySide{side(pubR), side(pubI)},
	}
}

// TestPlannerOutputClamped: a planner asking for everything gets the
// class ceiling, the protocol limits and only admitted targets.
func TestPlannerOutputClamped(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Planner = evilPlanner{} })
	p := r.pair(SessionOptions{})
	sums := p.summaries()
	for i, sum := range sums {
		r1 := sum.Plan.Round1
		if r1.Budget != protocol.BudgetLight || r1.Variant != "variant_1" || r1.Rescue || slices.ContainsFunc(r1.Sides, func(fs protocol.FamilySide) bool { return fs.Sandwich }) {
			t.Fatalf("round1 %+v", r1)
		}
		if r1.WindowMs > 10000 || len(r1.Sides) != 1 || sum.Plan.PairClass != "" {
			t.Fatalf("round1 sides %+v", r1)
		}
		lim, _ := protocol.BudgetLight.Limits()
		s := r1.Sides[0]
		if s.Role != protocol.SideReplyOnly && s.Role != protocol.SideSender && s.Role != protocol.SideReceiver && s.Role != protocol.SideBoth {
			t.Fatalf("role %q", s.Role)
		}
		if s.SendDelayMs > 3000 || int(s.Sockets) > int(lim.MaxSockets) || s.MaxPackets > lim.MaxPackets ||
			s.MaxPPS > lim.MaxPPS || s.MaxNewPerSec > 100 || s.MaxDistinctPorts > lim.MaxDistinctPorts || len(s.Stages) > 8 {
			t.Fatalf("side %d not clamped: %+v", i, s)
		}
		peer := pubR
		if i == 1 {
			peer = pubI
		}
		for _, st := range s.Stages {
			if st.Kind != protocol.StageDirect {
				t.Fatalf("relay-only plan has a %s stage", st.Kind)
			}
			if st.TTL != 0 && st.TTL < 2 || st.Repeats > 8 {
				t.Fatalf("stage %+v", st)
			}
			for _, tg := range st.Targets {
				if tg != peer {
					t.Fatalf("target %v admitted", tg)
				}
			}
		}
	}
	p.s.Abort(protocol.ReasonCanceled, "")
	res := r.wait(p.s)
	if res.Counters.PlanClamped == 0 || res.Counters.TargetRejected == 0 {
		t.Fatalf("counters %+v", res.Counters)
	}
	if len(r.waitEvents(EvPlanClamped, 1)) == 0 {
		t.Fatal("no clamp events")
	}
}

// TestPlannerWithoutTargets: a plan without one admitted target fails with
// no_probe_endpoint.
func TestPlannerWithoutTargets(t *testing.T) {
	r := newRig(t, func(c *Config) {
		c.Planner = evilPlanner{round: func(in plan.RoundInput) plan.RoundDecision {
			bad := []protocol.FamilySide{{Family: protocol.FamilyUDP4, Role: protocol.SideBoth, Sockets: 1, MaxPackets: 10,
				Stages: []protocol.Stage{{Kind: protocol.StageDirect, Targets: []netip.AddrPort{mustAP("8.8.4.4:53")}}}}}
			return plan.RoundDecision{Variant: 1, VariantName: "x", Budget: protocol.BudgetLight, Window: time.Second,
				Sides: [2][]protocol.FamilySide{bad, nil}}
		}}
	})
	p := r.pair(SessionOptions{})
	p.report(0)
	p.report(1)
	for i := range 2 {
		if a := expectAbort(t, p.cl[i]); a.Reason != protocol.ReasonNoProbeEndpoint {
			t.Fatalf("abort %+v", a)
		}
	}
	if res := r.wait(p.s); res.Reason != protocol.ReasonNoProbeEndpoint {
		t.Fatalf("result %+v", res)
	}
}

// TestPlannerStop: a planner stop ends the session with its reason, among
// them local_port_bind_failed, which is retried after 5 s.
func TestPlannerStop(t *testing.T) {
	cases := []struct {
		code  protocol.Reason
		retry RetryAdvice
	}{
		{protocol.ReasonHardSymmetricRandom, RetryAdvice{}},
		{protocol.ReasonLocalPortBindFailed, RetryAdvice{Retryable: true, After: retryBindFailed}},
	}
	for _, c := range cases {
		r := newRig(t, func(cfg *Config) {
			cfg.Planner = evilPlanner{round: func(plan.RoundInput) plan.RoundDecision { return plan.RoundDecision{Stop: c.code} }}
		})
		p := r.pair(SessionOptions{})
		p.report(0)
		p.report(1)
		if res := r.wait(p.s); res.Reason != c.code || res.Outcome != OutcomeFailed || res.Retry != c.retry {
			t.Fatalf("result %+v", res)
		}
	}
}

// TestPlannerUnknownReason: a stop reason outside the 26 is a planner defect.
func TestPlannerUnknownReason(t *testing.T) {
	r := newRig(t, func(c *Config) {
		c.Planner = evilPlanner{round: func(plan.RoundInput) plan.RoundDecision { return plan.RoundDecision{Stop: "made_up"} }}
	})
	p := r.pair(SessionOptions{})
	p.report(0)
	p.report(1)
	if res := r.wait(p.s); res.Reason != protocol.ReasonInternal {
		t.Fatalf("result %+v", res)
	}
}

// TestUnverifiedModeDirectOnly: the NoObserver mode needs its switch, marks
// the summary unverified and warns.
func TestUnverifiedModeDirectOnly(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("nil Registry without NoObserver accepted")
	}
	if _, err := New(Config{Registry: natprobe.NewRegistry(natprobe.RegistryConfig{}), NoObserver: true}); err == nil {
		t.Fatal("NoObserver with a Registry accepted")
	}
	if _, err := New(Config{NoObserver: true, TransportFallback: "a-very-long-transport-name"}); err == nil {
		t.Fatal("long fallback accepted")
	}
	bad := &protocol.Policy{Budget: protocol.Budget{Birthday: "huge"}}
	if _, err := New(Config{NoObserver: true, Policy: bad}); err == nil {
		t.Fatal("bad policy accepted")
	}
	r := newRig(t)
	p := r.pair(SessionOptions{})
	sums := p.summaries()
	for _, sum := range sums {
		if !maps.Equal(sum.Pair.Unverified, map[protocol.Family]bool{protocol.FamilyUDP4: true}) {
			t.Fatalf("unverified %v", sum.Pair.Unverified)
		}
		for _, s := range sum.Plan.Round1.Sides {
			targets := 0
			for _, st := range s.Stages {
				if st.Kind != protocol.StageDirect && st.Kind != protocol.StageReplyOnly || len(st.Targets) > 16 || st.Repeats > 8 {
					t.Fatalf("stage %+v", st)
				}
				targets += len(st.Targets)
			}
			if int(s.MaxPackets) > 8*targets {
				t.Fatalf("side %+v", s)
			}
		}
	}
	p.s.Abort(protocol.ReasonCanceled, "")
	if res := r.wait(p.s); !contains(res.Warn, protocol.WarnUnverifiedTargets) {
		t.Fatalf("warn %v", res.Warn)
	}
}

// testSession is a bare session for white-box tests of the planning helpers.
func testSession(t *testing.T, opts ...rigOpt) (*rig, *Session) {
	r := newRig(t, opts...)
	s := r.session(SessionOptions{ClientKeys: [2]string{"ik", "rk"}})
	s.st.adm.verified = [2]map[protocol.Family][]netip.Addr{
		{protocol.FamilyUDP4: {pubI.Addr()}},
		{protocol.FamilyUDP4: {pubR.Addr()}},
	}
	s.st.adm.lan = [2]map[protocol.Family][]netip.Addr{
		{protocol.FamilyUDP4: {localI.Addr()}},
		{protocol.FamilyUDP4: {localR.Addr()}},
	}
	s.st.reports = [2]*protocol.ProbeReport{{}, {}}
	s.st.plan.cls = plan.Classification{Families: []protocol.Family{protocol.FamilyUDP4}}
	t.Cleanup(func() { s.Abort(protocol.ReasonCanceled, "") })
	return r, s
}

// TestAdmission checks the target admission rules.
func TestAdmission(t *testing.T) {
	_, s := testSession(t, withRegistry(natprobe.NewRegistry(natprobe.RegistryConfig{})))
	s.mu.Lock()
	defer s.mu.Unlock()
	u4 := protocol.FamilyUDP4
	cases := []struct {
		a    netip.AddrPort
		want admitVerdict
	}{
		{pubR, admitPublic},
		{netip.AddrPortFrom(pubR.Addr(), 1), admitPublic}, // another port of a verified IP
		{mustAP("8.8.8.8:53"), admitRejected},
		{localR, admitRejected}, // private, but not the same site
		{mustAP("255.255.255.255:9"), admitRejected},
		{mustAP("[fe80::1]:9"), admitRejected},
		{netip.AddrPortFrom(pubR.Addr(), 0), admitRejected},
	}
	for _, c := range cases {
		if got := s.admitDirectLocked(1, u4, c.a, 1, 0); got != c.want {
			t.Errorf("%v: %v, want %v", c.a, got, c.want)
		}
	}
	// A private LAN address needs the same LAN, not only the same
	// public IP; a private port mapping (upstream-LAN candidate) needs the
	// same public IP, at its exact port.
	upstream := mustAP("100.64.1.2:4000")
	s.st.adm.upstream[1] = map[protocol.Family][]netip.AddrPort{u4: {upstream}}
	if s.admitDirectLocked(1, u4, upstream, 1, 0) != admitRejected {
		t.Fatal("upstream candidate without the same public IP")
	}
	s.st.adm.pair.SamePublicIP = map[protocol.Family]bool{u4: true}
	if got := s.admitDirectLocked(1, u4, localR, 1, 0); got != admitRejected {
		t.Fatalf("LAN target of another LAN behind the same public IP: %v", got)
	}
	if s.admitDirectLocked(1, u4, upstream, 1, 0) != admitLAN ||
		s.admitDirectLocked(1, u4, netip.AddrPortFrom(upstream.Addr(), 4001), 1, 0) != admitRejected {
		t.Fatal("upstream candidate")
	}
	s.st.adm.pair.LikelySameLAN = map[protocol.Family]bool{u4: true}
	if got := s.admitDirectLocked(1, u4, localR, 1, 0); got != admitLAN {
		t.Fatalf("same-LAN target: %v", got)
	}
	if !s.admitIPLocked(1, u4, pubR.Addr(), 1, 0) || s.admitIPLocked(1, u4, netip.MustParseAddr("8.8.8.8"), 1, 0) {
		t.Fatal("predict and random stages need a verified peer IP")
	}
	// Loopback is refused like at the client, even as a verified or
	// same-LAN address.
	loop := mustAP("127.0.0.1:4000")
	s.st.adm.verified[1][u4] = append(s.st.adm.verified[1][u4], loop.Addr())
	s.st.adm.lan[1][u4] = append(s.st.adm.lan[1][u4], loop.Addr())
	if got := s.admitDirectLocked(1, u4, loop, 1, 0); got != admitRejected {
		t.Fatalf("loopback target: %v", got)
	}
	if protocol.FamilyUDP6.UsableTarget(mustAP("[::1]:4000")) {
		t.Fatal("IPv6 loopback")
	}

	// Stages: private targets of a same-site peer get a stage of their own
	// with at most two packets each; predict needs a verified IP.
	stages := []protocol.Stage{
		{Kind: protocol.StageDirect, Targets: []netip.AddrPort{pubR, localR}, Repeats: 5, TTL: 99},
		{Kind: protocol.StagePredict, IP: pubR.Addr(), Anchor: 1, Steps: []int16{1, 1, 1, 1}, Span: 5000},
		{Kind: protocol.StageRandom, IP: netip.MustParseAddr("9.9.9.9"), Count: 1},
		{Kind: protocol.StageReplyOnly, AtMs: 7, Targets: []netip.AddrPort{pubR}},
	}
	out, sends, _ := s.clampStagesLocked(stageClamp(s), u4, stages, true)
	if !sends || len(out) != 4 {
		t.Fatalf("stages %+v", out)
	}
	if out[0].Targets[0] != pubR || out[0].TTL != protocol.MaxLowTTL || out[1].Targets[0] != localR || out[1].Repeats != protocol.LANRepeats {
		t.Fatalf("direct stages %+v", out[:2])
	}
	if out[2].Span != protocol.MaxSpanCount || len(out[2].Steps) != protocol.MaxSteps || out[3].Kind != protocol.StageReplyOnly || out[3].Targets != nil {
		t.Fatalf("other stages %+v", out[2:])
	}
	out, _, _ = s.clampStagesLocked(stageClamp(s), u4, stages[:1], false)
	if out[0].TTL != 0 {
		t.Fatal("ttl without low_ttl support")
	}

	// An unverified family: no predict or random stage, at most four
	// distinct public targets, eight packets per target; sixteen when no
	// family is verified.
	s.st.plan.cls.Families = []protocol.Family{protocol.FamilyUDP6, u4}
	s.st.adm.pair.Unverified = map[protocol.Family]bool{u4: true}
	if s.admitIPLocked(1, u4, pubR.Addr(), 1, 0) {
		t.Fatal("predict IP of an unverified family")
	}
	var many []netip.AddrPort
	for i := range 6 {
		many = append(many, netip.AddrPortFrom(pubR.Addr(), uint16(100+i)))
	}
	out, sends, n := s.clampStagesLocked(stageClamp(s), u4, []protocol.Stage{
		{Kind: protocol.StageDirect, Targets: many[:3], Repeats: 8},
		{Kind: protocol.StageDirect, Targets: many[2:], Repeats: 8},
		stages[1],
	}, true)
	if !sends || len(out) != 2 || !slices.Equal(out[1].Targets, many[2:4]) || n != 4 {
		t.Fatalf("unverified family stages %+v (%d targets)", out, n)
	}
	s.st.plan.cls.Families = []protocol.Family{u4}
	if out, _, n = s.clampStagesLocked(stageClamp(s), u4, []protocol.Stage{{Kind: protocol.StageDirect, Targets: many, Repeats: 8}}, true); n != len(many) || len(out[0].Targets) != len(many) {
		t.Fatalf("every family unverified: stages %+v (%d targets)", out, n)
	}
}

// TestFreshClamped: fresh stages aim only at
// what admission allows — a fresh_peer stage and a paired fresh stage at a
// verified IP, a fresh stage at verified endpoints — never in an unverified
// family or under NoPrediction, and fresh sockets come on top of the side's
// own within the socket ceiling.
func TestFreshClamped(t *testing.T) {
	_, s := testSession(t, withRegistry(natprobe.NewRegistry(natprobe.RegistryConfig{})))
	s.mu.Lock()
	defer s.mu.Unlock()
	u4 := protocol.FamilyUDP4
	nine := netip.MustParseAddr("9.9.9.9")
	stages := []protocol.Stage{
		{Kind: protocol.StageFresh, Count: 300, Repeats: 3, Targets: []netip.AddrPort{pubR, mustAP("8.8.8.8:53")}},
		{Kind: protocol.StageFreshPeer, IP: pubR.Addr(), Count: 5, Repeats: 3},
		{Kind: protocol.StageFreshPeer, IP: nine, Count: 5},
		{Kind: protocol.StageFresh, IP: nine, Count: 5},
	}
	out, sends, _ := s.clampStagesLocked(stageClamp(s), u4, stages, true)
	if !sends || len(out) != 2 || !slices.Equal(out[0].Targets, []netip.AddrPort{pubR}) || out[0].Count != protocol.MaxSideSockets ||
		out[1].Kind != protocol.StageFreshPeer || out[1].IP != pubR.Addr() {
		t.Fatalf("stages %+v", out)
	}
	capped, sends := s.capFreshLocked(1, slices.Clone(out), 6)
	if !sends || capped[0].Count != 6 {
		t.Fatalf("capped %+v", capped)
	}
	if capped, sends = s.capFreshLocked(1, slices.Clone(out[:1]), 0); sends || len(capped) != 0 {
		t.Fatalf("no room: %+v", capped)
	}
	s.ablate.NoPrediction = true
	if out, sends, _ = s.clampStagesLocked(stageClamp(s), u4, stages, true); sends || len(out) != 0 {
		t.Fatalf("NoPrediction kept %+v", out)
	}
	s.ablate.NoPrediction = false
	s.st.adm.pair.Unverified = map[protocol.Family]bool{u4: true}
	if out, sends, _ = s.clampStagesLocked(stageClamp(s), u4, stages, true); sends || len(out) != 0 {
		t.Fatalf("unverified family kept %+v", out)
	}
}

// TestEscalationGuard: the first round is at most min(class of Ladder[0],
// balanced) unless memory proved the variant; rounds rise one class at a
// time; heavy waits for round 2 with random-EDM evidence, else round 3;
// extreme needs AllowExtreme, round 3 and the keys' hourly allowance.
func TestEscalationGuard(t *testing.T) {
	_, s := testSession(t, func(c *Config) { c.Budget.AllowExtreme = true; c.Limits.ExtremePerHour = 1 })
	s.mu.Lock()
	defer s.mu.Unlock()
	st := &s.st
	// A ladder headed by a heavy variant: the first round still caps at
	// balanced.
	heavy := plan.VariantID(0)
	for v := range plan.VariantID(32) {
		if c, ok := engine.VariantClass(v); ok && c == protocol.BudgetHeavy {
			heavy = v
			break
		}
	}
	if heavy == 0 {
		t.Fatal("no heavy variant in the catalogue")
	}
	st.plan.cls.Ladder = []plan.VariantID{heavy}
	check := func(name string, k int, in, want protocol.BudgetClass) {
		t.Helper()
		if got := s.guardClassLocked(k, in, 0); got != want {
			t.Errorf("%s: %s → %s, want %s", name, in, got, want)
		}
	}
	check("first round cap", 1, protocol.BudgetExtreme, protocol.BudgetBalanced)
	check("invalid class", 1, "bogus", protocol.BudgetLight)
	st.plan.promoted = true
	check("proven variant", 1, protocol.BudgetHeavy, protocol.BudgetHeavy)
	st.plan.promoted = false
	st.rounds.lastGranted = protocol.BudgetLight
	check("one step", 2, protocol.BudgetHeavy, protocol.BudgetBalanced)
	st.rounds.lastGranted = protocol.BudgetBalanced
	check("heavy in round 2 without RND", 2, protocol.BudgetHeavy, protocol.BudgetBalanced)
	st.plan.pairRND = true
	check("heavy in round 2 with RND", 2, protocol.BudgetHeavy, protocol.BudgetHeavy)
	st.rounds.lastGranted = protocol.BudgetHeavy
	check("extreme in round 2", 2, protocol.BudgetExtreme, protocol.BudgetHeavy)
	check("extreme in round 3", 3, protocol.BudgetExtreme, protocol.BudgetExtreme)
	check("extreme allowance used", 4, protocol.BudgetExtreme, protocol.BudgetHeavy)
}

// TestDefaultPlannerFallback: a planner that panics is replaced by the
// default planner, which plans the rest of the session.
func TestDefaultPlannerFallback(t *testing.T) {
	for _, where := range []string{"classify", "round"} {
		t.Run(where, func(t *testing.T) {
			r := newRig(t, func(c *Config) { c.Planner = panicPlanner{where: where} })
			p := r.pair(SessionOptions{})
			sums := p.summaries()
			if sums[0].Plan.PairClass != engine.PairEasy {
				t.Fatalf("pair class %q", sums[0].Plan.PairClass)
			}
			p.s.Abort(protocol.ReasonCanceled, "")
			r.wait(p.s)
			if r.c.Stats().Panics == 0 || len(r.waitEvents(EvInternalError, 1)) == 0 {
				t.Fatal("planner panic not counted")
			}
		})
	}
}

type panicPlanner struct{ where string }

func (p panicPlanner) Classify(in plan.ClassifyInput) plan.Classification {
	if p.where == "classify" {
		panic("classify")
	}
	return engine.DefaultPlanner{}.Classify(in)
}

func (p panicPlanner) Round(_ plan.RoundInput) plan.RoundDecision {
	panic("round")
}

// sidePlanner plans every round as side(peer) for each role, peer being the
// other side's public address.
type sidePlanner struct {
	side func(peer netip.AddrPort) protocol.FamilySide
}

func (sidePlanner) Classify(in plan.ClassifyInput) plan.Classification {
	return engine.DefaultPlanner{}.Classify(in)
}

func (p sidePlanner) Round(in plan.RoundInput) plan.RoundDecision {
	return plan.RoundDecision{Variant: in.Class.Ladder[0], VariantName: "fixed", Budget: protocol.BudgetLight, Window: time.Second,
		Sides: [2][]protocol.FamilySide{{p.side(pubR)}, {p.side(pubI)}}}
}

// TestClampNeedNotKeepEquality: "MaxPackets is what the stages
// expand to" binds the Planner's output only. The clamp may leave a grant
// below the expansion — scaled to the remaining budget, or capped at 8 ×
// targets in an unverified family — or above it once admission dropped a
// target; it does not trim stages or raise grants to restore the equality,
// and a client sending its whole grant passes the audit.
func TestClampNeedNotKeepEquality(t *testing.T) {
	direct := func(sockets uint16, repeats uint8, extra ...netip.AddrPort) func(netip.AddrPort) protocol.FamilySide {
		return func(peer netip.AddrPort) protocol.FamilySide {
			targets := append([]netip.AddrPort{peer}, extra...)
			return protocol.FamilySide{Family: protocol.FamilyUDP4, Role: protocol.SideBoth, Sockets: sockets,
				MaxPackets: uint32(int(sockets) * len(targets) * int(repeats)), MaxPPS: 50, MaxNewPerSec: 50, MaxDistinctPorts: 4,
				Stages: []protocol.Stage{{Kind: protocol.StageDirect, Targets: targets, Repeats: repeats}}}
		}
	}
	cases := []struct {
		name   string
		side   func(netip.AddrPort) protocol.FamilySide
		limits Limits
		grant  uint32 // the round-1 grant after the clamp
		stages int    // what the clamped stages ask, as the planner counts them
	}{
		// 2 sockets × 8: the unverified family's cap is 8 × 1 target.
		{"unverified cap", direct(2, 8), Limits{}, 8, 16},
		// The key quota leaves 5 packets of the 6 planned.
		{"budget", direct(2, 3), Limits{PacketsPerMinute: [2]int{5, 5}}, 5, 6},
		// Admission drops 8.8.8.8: 5 packets left of a 10-packet grant.
		{"admission", direct(1, 5, mustAP("8.8.8.8:5000")), Limits{}, 8, 5},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, func(cfg *Config) { cfg.Planner = sidePlanner{side: c.side}; cfg.Limits = c.limits })
			p := r.pair(SessionOptions{ClientKeys: [2]string{"ik", "rk"}})
			sums := p.summaries()
			for i, sum := range sums {
				fs := sum.Plan.Round1.Sides[0]
				stages := 0
				for _, st := range fs.Stages {
					stages += int(fs.Sockets) * len(st.Targets) * int(st.Repeats)
				}
				if fs.MaxPackets != c.grant || stages != c.stages {
					t.Fatalf("side %d: grant %d for stages of %d packets (%s), want a grant of %d off the expansion",
						i, fs.MaxPackets, stages, fmt.Sprint(fs.Stages), c.grant)
				}
			}
			if c.name == "budget" {
				p.s.Abort(protocol.ReasonCanceled, "")
				r.wait(p.s)
				return
			}
			for i := range 2 {
				send(t, p.cl[i], simclient.Ready(sums[i], roleOf(i), 1))
			}
			expect[protocol.PunchGo](t, p.cl[0])
			expect[protocol.PunchGo](t, p.cl[1])
			full := simclient.Outcome{Family: protocol.FamilyUDP4, Sent: c.grant}
			if gos := p.endRound(1, [2]simclient.Outcome{full, full}); gos[0] == nil || gos[1] == nil {
				t.Fatal("no round 2 after both sides sent their whole grant")
			}
			p.s.Abort(protocol.ReasonCanceled, "")
			if res := r.wait(p.s); res.Reason != protocol.ReasonCanceled || res.Counters.PlanClamped == 0 {
				t.Fatalf("result %+v", res)
			}
		})
	}
}

// TestUnverifiedOverlayCeiling: in an unverified family the packet ceiling
// is eight per target the stages aim at, overlay targets included, so a
// shared overlay's stage does not eat the public targets' packets.
func TestUnverifiedOverlayCeiling(t *testing.T) {
	_, s := testSession(t)
	s.mu.Lock()
	defer s.mu.Unlock()
	u4 := protocol.FamilyUDP4
	ovl := mustAP("100.101.0.2:50000")
	st := &s.st
	st.adm.pair.Unverified = map[protocol.Family]bool{u4: true}
	st.adm.pair.SharedOverlay = map[protocol.Family]bool{u4: true}
	st.adm.overlay[1] = map[protocol.Family][]netip.Addr{u4: {ovl.Addr()}}
	side := protocol.FamilySide{Family: u4, Role: protocol.SideBoth, Sockets: 1, MaxPackets: protocol.UnverifiedRepeats + protocol.LANRepeats,
		MaxPPS: 50, MaxNewPerSec: 50, MaxDistinctPorts: 4, Stages: []protocol.Stage{
			{Kind: protocol.StageDirect, Targets: []netip.AddrPort{pubR}, Repeats: protocol.UnverifiedRepeats},
			{Kind: protocol.StageDirect, Targets: []netip.AddrPort{ovl}, Repeats: protocol.LANRepeats},
		}}
	if _, _, n := s.clampStagesLocked(stageClamp(s), u4, side.Stages, true); n != 2 {
		t.Fatalf("%d targets counted, want the public and the overlay one", n)
	}
	lim, _ := protocol.BudgetLight.Limits()
	out, active := s.clampSidesLocked(s.sideClampLocked(1, 0, lim, 0), []protocol.FamilySide{side})
	if !active || len(out) != 1 || out[0].MaxPackets != side.MaxPackets || len(out[0].Stages) != 2 {
		t.Fatalf("side %+v, want its %d packets kept", out, side.MaxPackets)
	}
}

// TestPlannerOutputSanitized: an unknown advice is dropped rather than
// failing the summary's encoding, and a stop detail is cut to what
// punch_abort carries.
func TestPlannerOutputSanitized(t *testing.T) {
	long := strings.Repeat("x", 3*protocol.MaxDetail)
	r := newRig(t, func(c *Config) { c.Planner = adviceStopPlanner{detail: long} })
	p := r.pair(SessionOptions{})
	sums := p.summaries()
	for i, sum := range sums {
		if sum.Plan.Advice != "" {
			t.Fatalf("side %d: advice %q", i, sum.Plan.Advice)
		}
		send(t, p.cl[i], simclient.Ready(sum, roleOf(i), 1))
	}
	for i := range 2 {
		expect[protocol.PunchGo](t, p.cl[i])
	}
	for i := range 2 {
		p.windowEnd(i, 1, fired(3))
	}
	for i := range 2 {
		if a := expectAbort(t, p.cl[i]); a.Reason != protocol.ReasonCandidateTimeout || a.Detail != long[:protocol.MaxDetail] {
			t.Fatalf("side %d: abort %s with a detail of %d bytes", i, a.Reason, len(a.Detail))
		}
	}
	if res := r.wait(p.s); res.Reason != protocol.ReasonCandidateTimeout || len(res.Detail) != protocol.MaxDetail || res.Retry.Advice != "" {
		t.Fatalf("result %s, detail of %d bytes, advice %q", res.Reason, len(res.Detail), res.Retry.Advice)
	}
}

// adviceStopPlanner is the default planner with an advice no client knows,
// stopping after round 1 with detail.
type adviceStopPlanner struct {
	engine.DefaultPlanner
	detail string
}

func (p adviceStopPlanner) Classify(in plan.ClassifyInput) plan.Classification {
	c := p.DefaultPlanner.Classify(in)
	c.Advice = "teleport"
	return c
}

func (p adviceStopPlanner) Round(in plan.RoundInput) plan.RoundDecision {
	if in.Round > 1 {
		return plan.RoundDecision{Stop: protocol.ReasonCandidateTimeout, StopDetail: p.detail}
	}
	return p.DefaultPlanner.Round(in)
}

// scribblePlanner is the default planner writing its input after reading
// it: the responder's endpoint in the classification views becomes a third
// party's, the round's classification loses its family, the policy forbids
// low TTL.
type scribblePlanner struct{ engine.DefaultPlanner }

var thirdParty = mustAP("8.8.8.8:53")

func (p scribblePlanner) Classify(in plan.ClassifyInput) plan.Classification {
	c := p.DefaultPlanner.Classify(in)
	for _, v := range []protocol.PeerView{in.Initiator, in.Responder} {
		for _, fv := range v.Families {
			for i := range fv.Endpoints {
				fv.Endpoints[i].Addr, fv.Endpoints[i].Verified = thirdParty, true
			}
		}
	}
	for f := range in.Pair.Unverified {
		in.Pair.Unverified[f] = false
	}
	return c
}

func (p scribblePlanner) Round(in plan.RoundInput) plan.RoundDecision {
	d := p.DefaultPlanner.Round(in)
	for i := range in.Class.Families {
		in.Class.Families[i] = "udp9"
	}
	if in.Policy.LowTTL != nil {
		*in.Policy.LowTTL = false
	}
	return d
}

// endpointsOf lists the endpoint addresses of a view.
func endpointsOf(v protocol.PeerView) []netip.AddrPort {
	var out []netip.AddrPort
	for _, fv := range v.Families {
		for _, e := range fv.Endpoints {
			out = append(out, e.Addr)
		}
	}
	return out
}

// TestPlannerInputPrivate: a planner that writes its input changes neither
// the admission sets nor the session's classification, policy or kept
// classification input.
func TestPlannerInputPrivate(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Planner = scribblePlanner{} })
	yes := true
	p := r.pair(SessionOptions{Policy: &protocol.Policy{LowTTL: &yes}})
	gos := p.punching()
	p.s.mu.Lock()
	sides := [2][]protocol.FamilySide{p.s.st.rounds.cur.plans[0].Sides, p.s.st.rounds.cur.plans[1].Sides}
	fams, unverified, lowTTL := slices.Clone(p.s.st.plan.cls.Families), p.s.st.adm.pair.Unverified[protocol.FamilyUDP4], *p.s.starts[0].Policy.LowTTL
	cin := p.s.st.plan.cin.Clone()
	p.s.mu.Unlock()
	for _, v := range []protocol.PeerView{cin.Initiator, cin.Responder} {
		if targets := endpointsOf(v); len(targets) == 0 || slices.Contains(targets, thirdParty) {
			t.Fatalf("kept classification input written: %v", targets)
		}
	}
	if !cin.Pair.Unverified[protocol.FamilyUDP4] {
		t.Fatal("kept classification input written: the family is verified")
	}
	for i := range 2 {
		if gos[i].Round != 1 || len(sides[i]) == 0 || sides[i][0].Role == protocol.SideReplyOnly {
			t.Fatalf("side %d: go %+v, sides %+v", i, gos[i], sides[i])
		}
		if slices.Contains(targetsOf(protocol.RoundPlan{Sides: sides[i]}), thirdParty) {
			t.Fatalf("side %d aims at the third party: %+v", i, sides[i])
		}
	}
	if !slices.Equal(fams, []protocol.Family{protocol.FamilyUDP4}) || !unverified || !lowTTL {
		t.Fatalf("session state written: families %v, unverified %v, low TTL %v", fams, unverified, lowTTL)
	}
	if gos := p.endRound(1, [2]simclient.Outcome{fired(3), fired(3)}); gos[0] == nil || gos[0].Round != 2 {
		t.Fatalf("round 2 go %+v", gos[0])
	}
	p.s.Abort(protocol.ReasonCanceled, "")
	r.wait(p.s)
}

// stageClamp is the clamp input of side 0's round 1 for clampStagesLocked
// alone, on a session that may have no reports.
func stageClamp(s *Session) sideClamp {
	st := &s.st
	return sideClamp{k: 1, r: 0, relayOnly: protocol.RelayOnly(st.plan.cls.Families, st.adm.pair, st.plan.views)}
}
