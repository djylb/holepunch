package protocol

import "time"

// Policy is a side's session policy: punch_start.policy from the server and
// holepunch.Options.Policy locally. Policies only ever tighten:
// CeilingBudget ≥ punch_start.policy ≥ summary.plan.budget ≥ each round's
// FamilySide ≥ Options.Policy. See Tighten.
type Policy struct {
	Budget      Budget            `json:"budget"`
	PortMapping PortMappingPolicy `json:"port_mapping"`
	LowTTL      *bool             `json:"low_ttl,omitempty"`      // nil: as the plan says
	LowTTLHops  []int             `json:"low_ttl_hops,omitempty"` // clamped to [2,32]; default {4,7}; <= 8 entries
}

// PortMappingPolicy enables port-mapping methods. A nil switch inherits the
// other level in Tighten and means "enabled" when the policy is applied.
type PortMappingPolicy struct {
	EnableUPnP   *bool  `json:"upnp,omitempty"`
	EnablePCP    *bool  `json:"pcp,omitempty"`
	EnableNATPMP *bool  `json:"natpmp,omitempty"`
	LeaseSeconds uint32 `json:"lease_seconds,omitempty"` // 0: DefaultPortMapLease
}

// DefaultPortMapLease is the lease requested when LeaseSeconds is unset.
const DefaultPortMapLease = time.Hour

// Enabled reports whether method m may be used; unset switches are on.
func (p PortMappingPolicy) Enabled(m PortMapMethod) bool {
	var sw *bool
	switch m {
	case PortMapUPnP:
		sw = p.EnableUPnP
	case PortMapPCP:
		sw = p.EnablePCP
	case PortMapNATPMP:
		sw = p.EnableNATPMP
	default:
		return false
	}
	return sw == nil || *sw
}

// Lease is the lease to request.
func (p PortMappingPolicy) Lease() time.Duration {
	if p.LeaseSeconds == 0 {
		return DefaultPortMapLease
	}
	return time.Duration(p.LeaseSeconds) * time.Second
}

// Budget is a side's session budget (each field: 0 = unset, see
// TightenBudget). The packet, rate and target limits apply to initiated
// packets only; replies and handshake packets have their own rules.
type Budget struct {
	MaxPackets         uint32       `json:"max_packets"`          // initiated UDP packets per session
	MaxPPS             uint16       `json:"max_pps"`              // token bucket shared by all sockets
	MaxDistinctTargets uint16       `json:"max_distinct_targets"` // distinct destination ip:port
	MaxSockets         uint16       `json:"max_sockets"`          // sockets open at once
	MaxNewPerSec       uint16       `json:"max_new_per_sec"`      // new targets per second
	Birthday           BirthdayTier `json:"birthday"`             // "" = unset
}

// DefaultBudget is the session budget when nothing tighter is configured:
// 3000 packets, 300 pps, 1024 targets, 40 sockets, 100 new targets/s,
// birthday conservative.
func DefaultBudget() Budget {
	return Budget{MaxPackets: 3000, MaxPPS: 300, MaxDistinctTargets: 1024, MaxSockets: 40, MaxNewPerSec: 100, Birthday: BirthdayConservative}
}

// CeilingBudget is the library's hard ceiling; no source can exceed it:
// 40000 / 1500 / 4096 / 256 / 256 / aggressive.
func CeilingBudget() Budget {
	return Budget{MaxPackets: 40000, MaxPPS: 1500, MaxDistinctTargets: 4096, MaxSockets: 256, MaxNewPerSec: 256, Birthday: BirthdayAggressive}
}

// SessionBudgetLimit is the highest session budget an operator may grant:
// CeilingBudget with AllowExtreme, otherwise 6000 / 1000 / 4096 / 128 / 256 /
// conservative (balanced and aggressive birthday need AllowExtreme).
func SessionBudgetLimit(allowExtreme bool) Budget {
	if allowExtreme {
		return CeilingBudget()
	}
	return Budget{MaxPackets: 6000, MaxPPS: 1000, MaxDistinctTargets: 4096, MaxSockets: 128, MaxNewPerSec: 256, Birthday: BirthdayConservative}
}

// TightenBudget merges budget levels from the outermost (levels[0], usually
// punch_start.policy.budget) to the innermost (for example Options.Policy).
// Each field of the result is the minimum over the levels, so a level can
// only tighten what is above it:
//
//   - a zero field of levels[0] means DefaultBudget's value;
//   - a zero field of a later level means "no further restriction";
//   - Birthday takes the lowest tier by Rank ("" = unset; an invalid name
//     counts as off);
//   - the result is clamped to CeilingBudget.
//
// With no levels the result is DefaultBudget.
func TightenBudget(levels ...Budget) Budget {
	def, ceil := DefaultBudget(), CeilingBudget()
	out := def
	if len(levels) > 0 {
		top := levels[0]
		out = Budget{
			MaxPackets:         orDefault(top.MaxPackets, def.MaxPackets),
			MaxPPS:             orDefault(top.MaxPPS, def.MaxPPS),
			MaxDistinctTargets: orDefault(top.MaxDistinctTargets, def.MaxDistinctTargets),
			MaxSockets:         orDefault(top.MaxSockets, def.MaxSockets),
			MaxNewPerSec:       orDefault(top.MaxNewPerSec, def.MaxNewPerSec),
			Birthday:           top.Birthday,
		}
		if out.Birthday == "" {
			out.Birthday = def.Birthday
		}
		for _, l := range levels[1:] {
			out.MaxPackets = minSet(out.MaxPackets, l.MaxPackets)
			out.MaxPPS = minSet(out.MaxPPS, l.MaxPPS)
			out.MaxDistinctTargets = minSet(out.MaxDistinctTargets, l.MaxDistinctTargets)
			out.MaxSockets = minSet(out.MaxSockets, l.MaxSockets)
			out.MaxNewPerSec = minSet(out.MaxNewPerSec, l.MaxNewPerSec)
			if l.Birthday != "" && l.Birthday.Rank() < out.Birthday.Rank() {
				out.Birthday = l.Birthday
			}
		}
	}
	out.MaxPackets = min(out.MaxPackets, ceil.MaxPackets)
	out.MaxPPS = min(out.MaxPPS, ceil.MaxPPS)
	out.MaxDistinctTargets = min(out.MaxDistinctTargets, ceil.MaxDistinctTargets)
	out.MaxSockets = min(out.MaxSockets, ceil.MaxSockets)
	out.MaxNewPerSec = min(out.MaxNewPerSec, ceil.MaxNewPerSec)
	if !out.Birthday.Valid() {
		out.Birthday = BirthdayOff
	}
	return out
}

func orDefault[T uint16 | uint32](v, def T) T {
	if v == 0 {
		return def
	}
	return v
}

func minSet[T uint16 | uint32](cur, v T) T {
	if v != 0 && v < cur {
		return v
	}
	return cur
}

// Tighten merges the server's policy (punch_start.policy) with the local one
// (Options.Policy); either may be nil. The local policy can only tighten:
//
//   - Budget: TightenBudget(server.Budget, local.Budget);
//   - LowTTL and the port-mapping switches: AND, nil inherits the other side,
//     both nil stays nil;
//   - LowTTLHops: the server's set (default {4,7}) clamped to [2,32]; a local
//     set keeps only the hops the server allows, and if none is left low TTL
//     is switched off;
//   - LeaseSeconds: the smaller non-zero value.
func Tighten(server, local *Policy) Policy {
	var s, l Policy
	if server != nil {
		s = *server
	}
	if local != nil {
		l = *local
	}
	out := Policy{
		Budget: TightenBudget(s.Budget, l.Budget),
		PortMapping: PortMappingPolicy{
			EnableUPnP:   andBool(s.PortMapping.EnableUPnP, l.PortMapping.EnableUPnP),
			EnablePCP:    andBool(s.PortMapping.EnablePCP, l.PortMapping.EnablePCP),
			EnableNATPMP: andBool(s.PortMapping.EnableNATPMP, l.PortMapping.EnableNATPMP),
			LeaseSeconds: minNonZero(s.PortMapping.LeaseSeconds, l.PortMapping.LeaseSeconds),
		},
		LowTTL: andBool(s.LowTTL, l.LowTTL),
	}
	hops := normalizeHops(s.LowTTLHops)
	if len(hops) == 0 {
		hops = []int{4, 7}
	}
	if want := normalizeHops(l.LowTTLHops); len(want) > 0 {
		var kept []int
		for _, h := range hops {
			for _, w := range want {
				if h == w {
					kept = append(kept, h)
					break
				}
			}
		}
		if len(kept) == 0 {
			off := false
			out.LowTTL = &off
		} else {
			hops = kept
		}
	}
	out.LowTTLHops = hops
	return out
}

func andBool(a, b *bool) *bool {
	switch {
	case a == nil && b == nil:
		return nil
	case a == nil:
		v := *b
		return &v
	case b == nil:
		v := *a
		return &v
	}
	v := *a && *b
	return &v
}

func minNonZero(a, b uint32) uint32 {
	switch {
	case a == 0:
		return b
	case b == 0:
		return a
	}
	return min(a, b)
}

// normalizeHops clamps hops to [2,32], drops duplicates and keeps at most 8,
// preserving order.
func normalizeHops(in []int) []int {
	var out []int
	for _, h := range in {
		h = min(max(h, 2), 32)
		dup := false
		for _, o := range out {
			dup = dup || o == h
		}
		if !dup && len(out) < maxLowTTLHops {
			out = append(out, h)
		}
	}
	return out
}

// ---- per-round budget classes ----

// ClassLimits is the per-round ceiling of a BudgetClass, per side.
type ClassLimits struct {
	MaxPackets       uint32
	MaxPPS           uint16
	MaxDistinctPorts uint16 // per peer IP per round
	MaxSockets       uint16
}

// Valid reports whether c is one of the four classes.
func (c BudgetClass) Valid() bool { return c.Rank() > 0 }

// Rank orders the classes: light 1, balanced 2, heavy 3, extreme 4; 0 for
// anything else. Consecutive rounds rise by at most one rank.
func (c BudgetClass) Rank() int {
	switch c {
	case BudgetLight:
		return 1
	case BudgetBalanced:
		return 2
	case BudgetHeavy:
		return 3
	case BudgetExtreme:
		return 4
	case BudgetBackground:
		return 3
	}
	return 0
}

// Limits is the class ceiling: light 150/80/16/2, balanced 800/200/64/8,
// heavy 3000/400/512/32, extreme 20000/1000/1024/128, background
// 2000/64/1152/128 (packets / pps / distinct ports / sockets). ok is false
// for an invalid class.
func (c BudgetClass) Limits() (l ClassLimits, ok bool) {
	switch c {
	case BudgetLight:
		return ClassLimits{150, 80, 16, 2}, true
	case BudgetBalanced:
		return ClassLimits{800, 200, 64, 8}, true
	case BudgetHeavy:
		return ClassLimits{3000, 400, 512, 32}, true
	case BudgetExtreme:
		return ClassLimits{20000, 1000, 1024, 128}, true
	case BudgetBackground:
		return ClassLimits{2000, 64, 1152, 128}, true
	}
	return ClassLimits{}, false
}

// Round windows: 10 s, and 45 s for the slow
// birthday of a Background session.
const (
	maxWindowMs           = 10000
	maxBackgroundWindowMs = 45000
)

// MaxWindowMs is the longest window_ms of a round of class c.
func (c BudgetClass) MaxWindowMs() uint16 {
	if c == BudgetBackground {
		return maxBackgroundWindowMs
	}
	return maxWindowMs
}

// BackgroundBudget is the default session budget of a Background session:
// DefaultBudget with the 128 sockets and 2048 distinct targets the slow
// birthday needs — both within SessionBudgetLimit(false).
func BackgroundBudget() Budget {
	b := DefaultBudget()
	b.MaxSockets, b.MaxDistinctTargets = 128, 2048
	return b
}

// RequiresExtreme reports whether the class needs AllowExtreme.
func (c BudgetClass) RequiresExtreme() bool { return c == BudgetExtreme }

// ---- birthday tiers ----

// BirthdaySpec is the scale of a birthday tier: the one-sided birthday opens
// OneSidedSockets sockets on one side against OneSidedTargets random ports of
// the other; the two-sided birthday (aggressive only) opens TwoSidedSockets
// per side against TwoSidedTargets. Class is the BudgetClass the round needs.
type BirthdaySpec struct {
	OneSidedSockets, OneSidedTargets int
	TwoSidedSockets, TwoSidedTargets int
	Class                            BudgetClass
	RequiresExtreme                  bool
	MinHandshakeMs                   uint32 // aggressive: handshake_timeout_ms >= 30000
}

// Valid reports whether t is one of the four tiers.
func (t BirthdayTier) Valid() bool { return t == BirthdayOff || t.Rank() > 0 }

// Rank orders the tiers: off 0, conservative 1, balanced 2, aggressive 3;
// -1 for anything else.
func (t BirthdayTier) Rank() int {
	switch t {
	case BirthdayOff:
		return 0
	case BirthdayConservative:
		return 1
	case BirthdayBalanced:
		return 2
	case BirthdayAggressive:
		return 3
	}
	return -1
}

// Spec is the tier's scale: conservative 32×384 (heavy), balanced 64×768
// (extreme), aggressive 128×1000 + two-sided 16×256 (extreme, handshake >=
// 30 s).
// ok is false for off and invalid tiers.
func (t BirthdayTier) Spec() (s BirthdaySpec, ok bool) {
	switch t {
	case BirthdayConservative:
		return BirthdaySpec{OneSidedSockets: 32, OneSidedTargets: 384, Class: BudgetHeavy}, true
	case BirthdayBalanced:
		return BirthdaySpec{OneSidedSockets: 64, OneSidedTargets: 768, Class: BudgetExtreme, RequiresExtreme: true}, true
	case BirthdayAggressive:
		return BirthdaySpec{OneSidedSockets: 128, OneSidedTargets: 1000, TwoSidedSockets: 16, TwoSidedTargets: 256,
			Class: BudgetExtreme, RequiresExtreme: true, MinHandshakeMs: 30000}, true
	}
	return BirthdaySpec{}, false
}
