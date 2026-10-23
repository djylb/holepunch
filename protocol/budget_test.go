package protocol

import (
	"encoding/base64"
	"go/parser"
	"go/token"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/wiretype"
)

func TestBudgetConstants(t *testing.T) {
	if got := DefaultBudget(); got != (Budget{3000, 300, 1024, 40, 100, BirthdayConservative}) {
		t.Errorf("DefaultBudget = %+v", got)
	}
	if got := CeilingBudget(); got != (Budget{40000, 1500, 4096, 256, 256, BirthdayAggressive}) {
		t.Errorf("CeilingBudget = %+v", got)
	}
	if got := SessionBudgetLimit(false); got != (Budget{6000, 1000, 4096, 128, 256, BirthdayConservative}) {
		t.Errorf("SessionBudgetLimit(false) = %+v", got)
	}
	if SessionBudgetLimit(true) != CeilingBudget() {
		t.Error("SessionBudgetLimit(true)")
	}
	for _, tc := range []struct {
		c    BudgetClass
		l    ClassLimits
		rank int
	}{
		{BudgetLight, ClassLimits{150, 80, 16, 2}, 1},
		{BudgetBalanced, ClassLimits{800, 200, 64, 8}, 2},
		{BudgetHeavy, ClassLimits{3000, 400, 512, 32}, 3},
		{BudgetExtreme, ClassLimits{20000, 1000, 1024, 128}, 4},
	} {
		if l, ok := tc.c.Limits(); !ok || l != tc.l || tc.c.Rank() != tc.rank || !tc.c.Valid() || tc.c.RequiresExtreme() != (tc.c == BudgetExtreme) {
			t.Errorf("%s: limits %+v rank %d", tc.c, l, tc.c.Rank())
		}
	}
	if _, ok := BudgetClass("medium").Limits(); ok || BudgetClass("").Valid() {
		t.Error("invalid class accepted")
	}
	for _, tc := range []struct {
		tier BirthdayTier
		rank int
		spec BirthdaySpec
		ok   bool
	}{
		{BirthdayOff, 0, BirthdaySpec{}, false},
		{BirthdayConservative, 1, BirthdaySpec{OneSidedSockets: 32, OneSidedTargets: 384, Class: BudgetHeavy}, true},
		{BirthdayBalanced, 2, BirthdaySpec{OneSidedSockets: 64, OneSidedTargets: 768, Class: BudgetExtreme, RequiresExtreme: true}, true},
		{BirthdayAggressive, 3, BirthdaySpec{OneSidedSockets: 128, OneSidedTargets: 1000, TwoSidedSockets: 16, TwoSidedTargets: 256, Class: BudgetExtreme, RequiresExtreme: true, MinHandshakeMs: 30000}, true},
	} {
		spec, ok := tc.tier.Spec()
		if tc.tier.Rank() != tc.rank || spec != tc.spec || ok != tc.ok || !tc.tier.Valid() {
			t.Errorf("%s: rank %d spec %+v ok %v", tc.tier, tc.tier.Rank(), spec, ok)
		}
		// Every tier's per-socket and per-port needs fit in its class.
		if l, okc := spec.Class.Limits(); ok && (!okc || spec.OneSidedSockets > int(l.MaxSockets)) {
			t.Errorf("%s: %d sockets exceed class %s", tc.tier, spec.OneSidedSockets, spec.Class)
		}
	}
	if BirthdayTier("").Valid() || BirthdayTier("max").Rank() != -1 {
		t.Error("invalid tier accepted")
	}
}

func randBudget(r *rand.Rand) Budget {
	pick := func(max int) int {
		if r.IntN(4) == 0 {
			return 0 // unset
		}
		return r.IntN(max) + 1
	}
	tiers := []BirthdayTier{"", BirthdayOff, BirthdayConservative, BirthdayBalanced, BirthdayAggressive, "bogus"}
	return Budget{
		MaxPackets:         uint32(pick(60000)),
		MaxPPS:             uint16(pick(3000)),
		MaxDistinctTargets: uint16(pick(8000)),
		MaxSockets:         uint16(pick(600)),
		MaxNewPerSec:       uint16(pick(600)),
		Birthday:           tiers[r.IntN(len(tiers))],
	}
}

// budgetFields flattens the numeric fields and the birthday rank.
func budgetFields(b Budget) []int {
	return []int{int(b.MaxPackets), int(b.MaxPPS), int(b.MaxDistinctTargets), int(b.MaxSockets), int(b.MaxNewPerSec), b.Birthday.Rank()}
}

// effective is a level's value as an upper bound: levels[0] zero → default,
// later zero → unbounded.
func effective(b Budget, top bool) []int {
	f := budgetFields(b)
	def := budgetFields(DefaultBudget())
	for i := range f {
		switch {
		case i == 5 && b.Birthday == "":
			f[i] = 1 << 30
			if top {
				f[i] = def[i]
			}
		case i == 5 && !b.Birthday.Valid():
			f[i] = 0 // an invalid tier counts as off
		case i == 5:
			// a valid tier (off has rank 0)
		case f[i] == 0 && top:
			f[i] = def[i]
		case f[i] == 0:
			f[i] = 1 << 30
		}
	}
	return f
}

// TestTightenBudgetProperties: the merged budget never exceeds the ceiling or
// any level; it equals the minimum of the levels; it is idempotent; later
// levels commute; tightening an input never loosens the result.
func TestTightenBudgetProperties(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	ceil := budgetFields(CeilingBudget())
	for iter := 0; iter < 20000; iter++ {
		levels := make([]Budget, 1+r.IntN(4))
		for i := range levels {
			levels[i] = randBudget(r)
		}
		got := TightenBudget(levels...)
		g := budgetFields(got)
		if !got.Birthday.Valid() {
			t.Fatalf("invalid birthday %q", got.Birthday)
		}
		for i := range g {
			want := ceil[i]
			for j, l := range levels {
				want = min(want, effective(l, j == 0)[i])
			}
			if g[i] != want {
				t.Fatalf("iter %d field %d: got %d, want min %d (levels %+v)", iter, i, g[i], want, levels)
			}
			if g[i] == 0 && i < 5 {
				t.Fatalf("iter %d: field %d is 0", iter, i)
			}
		}
		if again := TightenBudget(got, got); again != got {
			t.Fatalf("not idempotent: %+v → %+v", got, again)
		}
		if again := TightenBudget(got); again != got {
			t.Fatalf("a complete budget changed alone: %+v → %+v", got, again)
		}
		if len(levels) >= 3 {
			swapped := slices.Clone(levels)
			swapped[1], swapped[2] = swapped[2], swapped[1]
			if TightenBudget(swapped...) != got {
				t.Fatalf("later levels do not commute: %+v", levels)
			}
		}
		// Monotone: adding a level, or tightening one, never loosens.
		extra := randBudget(r)
		tighter := budgetFields(TightenBudget(append(slices.Clone(levels), extra)...))
		for i := range g {
			if tighter[i] > g[i] {
				t.Fatalf("adding a level loosened field %d: %d > %d", i, tighter[i], g[i])
			}
		}
	}
	if TightenBudget() != DefaultBudget() {
		t.Error("TightenBudget() != DefaultBudget()")
	}
	if got := TightenBudget(Budget{}, Budget{MaxPackets: 6000}); got.MaxPackets != 3000 {
		t.Errorf("an unset server field is the default; local 6000 must not loosen it: %d", got.MaxPackets)
	}
}

func boolp(r *rand.Rand) *bool {
	switch r.IntN(3) {
	case 0:
		return nil
	case 1:
		return ptr(true)
	}
	return ptr(false)
}

func TestTightenPolicyProperties(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	randPolicy := func() *Policy {
		if r.IntN(5) == 0 {
			return nil
		}
		p := &Policy{Budget: randBudget(r), LowTTL: boolp(r),
			PortMapping: PortMappingPolicy{EnableUPnP: boolp(r), EnablePCP: boolp(r), EnableNATPMP: boolp(r), LeaseSeconds: uint32(r.IntN(3)) * 1800}}
		for n := r.IntN(4); n > 0; n-- {
			p.LowTTLHops = append(p.LowTTLHops, r.IntN(40))
		}
		return p
	}
	val := func(p *Policy, f func(*Policy) *bool) *bool {
		if p == nil {
			return nil
		}
		return f(p)
	}
	for iter := 0; iter < 20000; iter++ {
		s, l := randPolicy(), randPolicy()
		got := Tighten(s, l)
		var sb, lb Budget
		if s != nil {
			sb = s.Budget
		}
		if l != nil {
			lb = l.Budget
		}
		if got.Budget != TightenBudget(sb, lb) {
			t.Fatal("budget")
		}
		// Port-mapping switches: AND with nil inheriting (LowTTL is checked
		// below because the hops rule may also switch it off).
		for _, sw := range []func(*Policy) *bool{
			func(p *Policy) *bool { return p.PortMapping.EnableUPnP },
			func(p *Policy) *bool { return p.PortMapping.EnablePCP },
			func(p *Policy) *bool { return p.PortMapping.EnableNATPMP },
		} {
			a, b, out := val(s, sw), val(l, sw), sw(&got)
			switch {
			case a == nil && b == nil:
				if out != nil {
					t.Fatal("nil switches must stay nil")
				}
			case out == nil:
				t.Fatal("switch lost")
			case (a != nil && !*a) || (b != nil && !*b):
				if *out {
					t.Fatal("a disabled switch was enabled")
				}
			case !*out:
				t.Fatal("an enabled switch was disabled")
			}
		}
		sOff := s != nil && s.LowTTL != nil && !*s.LowTTL
		lOff := l != nil && l.LowTTL != nil && !*l.LowTTL
		if (sOff || lOff) && (got.LowTTL == nil || *got.LowTTL) {
			t.Fatal("low TTL disabled by a side came back on")
		}
		if (s == nil || s.LowTTL == nil) && (l == nil || l.LowTTL == nil) && got.LowTTL != nil && *got.LowTTL {
			t.Fatal("low TTL switched on although nobody asked")
		}
		allowed := []int{4, 7}
		if s != nil && len(normalizeHops(s.LowTTLHops)) > 0 {
			allowed = normalizeHops(s.LowTTLHops)
		}
		for _, h := range got.LowTTLHops {
			if h < 2 || h > 32 || !slices.Contains(allowed, h) {
				t.Fatalf("hop %d outside the server set %v", h, allowed)
			}
		}
		if lease := got.PortMapping.LeaseSeconds; s != nil && l != nil && s.PortMapping.LeaseSeconds != 0 && l.PortMapping.LeaseSeconds != 0 &&
			lease != min(s.PortMapping.LeaseSeconds, l.PortMapping.LeaseSeconds) {
			t.Fatal("lease")
		}
		if again := Tighten(&got, l); again.Budget != got.Budget {
			t.Fatal("re-tightening with the same local policy changed the budget")
		}
	}
	// A local hop set disjoint from the server's switches low TTL off.
	off := Tighten(&Policy{LowTTLHops: []int{4, 7}}, &Policy{LowTTLHops: []int{9}})
	if off.LowTTL == nil || *off.LowTTL || !slices.Equal(off.LowTTLHops, []int{4, 7}) {
		t.Fatalf("disjoint hops: %+v", off)
	}
	sub := Tighten(nil, &Policy{LowTTLHops: []int{7, 1}})
	if sub.LowTTL != nil || !slices.Equal(sub.LowTTLHops, []int{7}) {
		t.Fatalf("subset hops: %+v %v", sub.LowTTL, sub.LowTTLHops)
	}
}

func TestIdentities(t *testing.T) {
	ids := map[string]bool{}
	tokens := map[Token]bool{}
	for i := 0; i < 100; i++ {
		id := NewSessionID()
		if len(id) != 24 || checkSessionID(id) != nil || ids[id] {
			t.Fatalf("NewSessionID = %q", id)
		}
		ids[id] = true
		tok := NewToken()
		if tok.IsZero() || tokens[tok] {
			t.Fatal("NewToken repeated or zero")
		}
		tokens[tok] = true
		text, _ := tok.MarshalText()
		if b, err := base64.RawURLEncoding.DecodeString(string(text)); err != nil || len(b) != 32 || [32]byte(b) != tok {
			t.Fatalf("token text %q", text)
		}
	}
	c := DefaultControlSpec()
	if c.Version != wiretype.Version || !slices.Equal(c.Features, []Feature{"sandwich"}) {
		t.Fatalf("DefaultControlSpec = %+v", c)
	}
	// Unknown features (including names no implementation offers) are ignored.
	got := AcceptFeatures([]Feature{"future", "sandwich", "rounds", "peer_seen", "sandwich"}, SupportedFeatures())
	if !slices.Equal(got, []Feature{"sandwich"}) {
		t.Fatalf("AcceptFeatures = %v", got)
	}
	if AcceptFeatures(nil, SupportedFeatures()) != nil || !c.Has(FeatureSandwich) || (ControlSpec{}).Has(FeatureSandwich) {
		t.Fatal("features")
	}
}

// TestPayloadRangePerSession checks the per-session payload range: payload_min ∈
// [48,160], payload_max − payload_min ∈ [64,256], payload_max ≤ 1024, every
// value reachable, and sessions get different ranges.
func TestPayloadRangePerSession(t *testing.T) {
	mins, spans, ranges := map[uint16]int{}, map[uint16]int{}, map[[2]uint16]int{}
	routes := map[RouteID]bool{}
	const n = 10000
	for i := 0; i < n; i++ {
		w := NewWireSpec()
		span := w.PayloadMax - w.PayloadMin
		_, clamped := w.Normalize()
		if w.PayloadMin < 48 || w.PayloadMin > 160 || span < 64 || span > 256 || w.PayloadMax > 1024 || clamped {
			t.Fatalf("NewWireSpec = %+v", w)
		}
		if w.RouteID.IsZero() || routes[w.RouteID] {
			t.Fatalf("route %v repeated or zero", w.RouteID)
		}
		routes[w.RouteID] = true
		mins[w.PayloadMin]++
		spans[span]++
		ranges[[2]uint16{w.PayloadMin, w.PayloadMax}]++
	}
	if len(mins) != 113 || len(spans) != 193 {
		t.Fatalf("saw %d of 113 minimums and %d of 193 spans", len(mins), len(spans))
	}
	// Same range for two sessions: expected 1/(113·193) per pair; the most
	// common range must stay near n/(113·193) ≈ 0.46.
	for r, c := range ranges {
		if c > 8 {
			t.Fatalf("range %v drawn %d times out of %d", r, c, n)
		}
	}
}

func TestTraitsPredicates(t *testing.T) {
	cone := Traits{Mapping: MapEIM, MappingConf: ConfMedium, Filtering: FiltNotPDF}
	pdf := Traits{Mapping: MapEIM, MappingConf: ConfHigh, Filtering: FiltPDF}
	seq := Traits{Mapping: MapAPDM, MappingConf: ConfHigh, PortAlloc: AllocSequential, PortAllocConf: ConfMedium, Filtering: FiltPDF}
	poolLow := Traits{Mapping: MapAPDM, PortAlloc: AllocPool, PortAllocConf: ConfLow}
	admSeq := Traits{Mapping: MapADM, MappingConf: ConfHigh, PortAlloc: AllocSequential, PortAllocConf: ConfHigh, Filtering: FiltNotPDF}
	eimSeq := Traits{Mapping: MapEIM, MappingConf: ConfHigh, PortAlloc: AllocSequential, PortAllocConf: ConfHigh, Filtering: FiltNotPDF}
	public := Traits{NoNAT: TriTrue, Filtering: FiltEIF}
	multi := Traits{Mapping: MapUnknown, MappingConf: ConfLow, MultiExit: true}
	for _, tc := range []struct {
		name                                         string
		t                                            Traits
		usable, simul, afterIP, dependent, pred, unc bool
	}{
		{"cone", cone, true, false, true, false, false, false},
		{"pdf", pdf, true, true, false, false, false, false},
		{"seq", seq, false, true, false, true, true, false},
		{"pool_low", poolLow, false, true, false, true, false, true},
		{"public", public, true, false, true, false, false, true},
		{"multi_exit", multi, false, true, false, true, false, true},
		{"adm_seq_predictable", admSeq, false, false, true, true, true, false},
		{"eim_never_predicted", eimSeq, true, false, true, false, false, false},
	} {
		got := []bool{tc.t.ObservedUsable(), tc.t.NeedsSimultaneous(), tc.t.AcceptsAfterIPContact(), tc.t.EndpointDependent(), tc.t.Predictable(), tc.t.Uncertain()}
		want := []bool{tc.usable, tc.simul, tc.afterIP, tc.dependent, tc.pred, tc.unc}
		if !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", tc.name, got, want)
		}
	}
	if !NeedsPeerPortPrediction(pdf, seq) || NeedsPeerPortPrediction(cone, seq) || NeedsPeerPortPrediction(pdf, cone) {
		t.Error("NeedsPeerPortPrediction")
	}
}

// TestDependencyRules checks the import rules of this module's packages:
// protocol → std + internal/wiretype + internal/netaddr;
// internal/controlwire → std + internal/wiretype + internal/life +
// internal/faultinject; internal/life → std + internal/trunc;
// internal/wiretype, internal/trunc, internal/netaddr and the standalone
// tool packages (stun, udpsock, hostaddr, clock) → std.
func TestDependencyRules(t *testing.T) {
	const module = "github.com/djylb/holepunch"
	allowed := map[string][]string{
		"protocol":             {module + "/internal/wiretype", module + "/internal/netaddr"},
		"internal/controlwire": {module + "/internal/wiretype", module + "/internal/life", module + "/internal/faultinject"},
		"internal/wiretype":    nil,
		"internal/life":        {module + "/internal/trunc"},
		"internal/trunc":       nil,
		"internal/netaddr":     nil,
		"stun":                 nil,
		"udpsock":              nil,
		"hostaddr":             nil,
		"clock":                nil,
	}
	for dir, extra := range allowed {
		files, err := filepath.Glob(filepath.Join("..", dir, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("%s: %v", dir, err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			file, err := parser.ParseFile(token.NewFileSet(), f, src, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range file.Imports {
				path, _ := strconv.Unquote(imp.Path.Value)
				first, _, _ := strings.Cut(path, "/")
				if !strings.Contains(first, ".") {
					continue // standard library
				}
				if !slices.Contains(extra, path) {
					t.Errorf("%s imports %s", f, path)
				}
			}
		}
	}
}

func TestPortMappingPolicy(t *testing.T) {
	var p PortMappingPolicy
	for _, m := range []PortMapMethod{PortMapUPnP, PortMapPCP, PortMapNATPMP} {
		if !p.Enabled(m) {
			t.Errorf("%s disabled by default", m)
		}
	}
	if p.Enabled("stun") || p.Lease() != DefaultPortMapLease {
		t.Fatal("unknown method or default lease")
	}
	off := false
	p = PortMappingPolicy{EnablePCP: &off, LeaseSeconds: 90}
	if p.Enabled(PortMapPCP) || !p.Enabled(PortMapUPnP) || p.Lease() != 90*time.Second {
		t.Fatalf("policy %+v", p)
	}
	info := PortMappingInfo{Method: PortMapPCP, External: ap("198.51.100.7:4000"), Internal: ap("10.0.0.2:5000"), Lease: 1500 * time.Millisecond}
	if r := info.Report(); r.LeaseSeconds != 1 || r.Method != PortMapPCP || r.External != info.External {
		t.Fatalf("Report = %+v", r)
	}
	if r := (PortMappingInfo{Lease: -time.Second}).Report(); r.LeaseSeconds != 0 {
		t.Fatalf("negative lease = %d", r.LeaseSeconds)
	}
}

// TestBackgroundMode: the background class
// ranks with heavy, takes a 45 s window that no other class gets, and the
// background session budget stays within what an operator may grant
// without AllowExtreme; modes and advice are closed sets.
func TestBackgroundMode(t *testing.T) {
	l, ok := BudgetBackground.Limits()
	if !ok || l.MaxSockets != 128 || l.MaxDistinctPorts != 1152 || BudgetBackground.Rank() != BudgetHeavy.Rank() ||
		BudgetBackground.RequiresExtreme() || BudgetBackground.MaxWindowMs() != 45000 || BudgetHeavy.MaxWindowMs() != 10000 {
		t.Fatalf("background class %+v", l)
	}
	if b, lim := BackgroundBudget(), SessionBudgetLimit(false); TightenBudget(b, lim) != b || b.MaxSockets < l.MaxSockets {
		t.Fatalf("background budget %+v beyond %+v", b, lim)
	}
	rp := RoundPlan{Round: 2, Variant: "slow", Budget: BudgetBackground, WindowMs: 60000, Seed: 1,
		Sides: []FamilySide{{Family: FamilyUDP4, Role: SideBoth, Sockets: 1, OpenPerSec: 999, Stages: []Stage{{Kind: StageReplyOnly}}}}}
	rp, clamped := rp.Normalize()
	if !clamped || rp.WindowMs != 45000 || rp.Sides[0].OpenPerSec != CeilingBudget().MaxNewPerSec {
		t.Fatalf("normalized %d ms, %d/s", rp.WindowMs, rp.Sides[0].OpenPerSec)
	}
	g, clamped := PunchGo{SessionID: "s", Round: 2, WindowMs: 60000, Plan: &rp}.Normalize()
	if !clamped || g.WindowMs != 45000 || g.Validate() != nil {
		t.Fatalf("go window %d: %v", g.WindowMs, g.Validate())
	}
	rp.Budget = BudgetHeavy
	g, clamped = PunchGo{SessionID: "s", Round: 2, WindowMs: 45000, Plan: &rp}.Normalize()
	if !clamped || g.WindowMs != 10000 || g.Plan.WindowMs != 10000 {
		t.Fatalf("heavy go window %d / plan %d", g.WindowMs, g.Plan.WindowMs)
	}
	for _, m := range []SessionMode{"", ModeInteractive, ModeBackground} {
		if !m.Valid() {
			t.Errorf("mode %q invalid", m)
		}
	}
	if SessionMode("lazy").Valid() || Advice("retry").Valid() || !Advice("").Valid() || !AdviceRelayOnly.Valid() {
		t.Error("closed sets")
	}
}

func TestClassOfRank(t *testing.T) {
	for r, want := range map[int]BudgetClass{-1: BudgetLight, 0: BudgetLight, 1: BudgetLight, 2: BudgetBalanced, 3: BudgetHeavy, 4: BudgetExtreme, 9: BudgetExtreme} {
		if got := ClassOfRank(r); got != want {
			t.Errorf("ClassOfRank(%d) = %s, want %s", r, got, want)
		}
	}
	for _, c := range []BudgetClass{BudgetLight, BudgetBalanced, BudgetHeavy, BudgetExtreme} {
		if ClassOfRank(c.Rank()) != c {
			t.Errorf("%s does not round-trip", c)
		}
	}
	if BudgetHeavy.Min(BudgetBalanced) != BudgetBalanced || BudgetLight.Min(BudgetExtreme) != BudgetLight ||
		BudgetHeavy.Min(BudgetBackground) != BudgetHeavy || BudgetBackground.Min(BudgetHeavy) != BudgetBackground {
		t.Error("Min")
	}
}
