package coord

import (
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/protocol"
)

// Protocol-level plan limits.
const (
	maxSendDelayMs = 3000
	maxSockets     = 256
	maxPPS         = 1500
	maxNewPerSec   = 256
	maxStages      = 8
	maxTargets     = 16
	maxSpan        = 4096
	maxSteps       = 3
	maxRepeats     = 8
	minTTL         = 2
	maxTTL         = 64
	maxLANTargets  = 4 // private targets of a peer on the same LAN or upstream NAT, per round and side
	maxOverlay     = 2 // overlay targets of a peer that shares an overlay, per round and side
	lanRepeats     = 2 // packets per private target and round
	maxWindowWidth = 63

	// Unverified families: Direct stages only, to at most this many
	// distinct targets per side and round — 16 when every family is
	// unverified (the relay-only mode), else 4 — and at most 8 packets per
	// target and round. The targets lie on the first reportedIPs distinct
	// global IPs the peer reported: the ones its client admits.
	maxRelayOnlyTargets  = 16
	maxUnverifiedTargets = 4
	unverifiedPerTarget  = 8
	reportedIPs          = 4
)

// prepareRoundLocked turns a planner decision into the two sides' RoundPlans
// without trusting it: the budget class passes the escalation guard,
// the window is clamped, each side is clamped to the class, the session and
// key budgets, the host's capabilities and the protocol limits, and every
// target passes admission. It charges the grants and makes the plan the
// round under way; it fails with no_probe_endpoint when neither side keeps a
// stage that sends.
func (s *Session) prepareRoundLocked(k int, dec RoundDecision, now time.Duration) *terminal {
	st := &s.st
	name := dec.VariantName
	if !isName(name) {
		name = fmt.Sprintf("variant_%d", dec.Variant)
		s.clampedLocked(k, "variant", 0, 0)
	}
	// One rescue round per session, and only right after a one-way round.
	rescue := dec.Rescue && !st.rescueUsed && !s.ablate.NoRounds && len(st.prev) > 0 &&
		st.prev[len(st.prev)-1].Class == RoundOneWay
	if dec.Rescue && !rescue {
		s.clampedLocked(k, "rescue", 1, 0)
	}
	class := s.guardClassLocked(k, dec.Budget, now)
	lim, _ := class.Limits()

	a := align([2]*rttEstimator{&st.rtt[0], &st.rtt[1]}, s.ablate.NoRTTAlign)
	hi := max(min(s.remainingLocked(now)-a.d, time.Duration(class.MaxWindowMs())*time.Millisecond), minWindow)
	win := clampDur(dec.Window, minWindow, hi)
	if win != dec.Window {
		s.clampedLocked(k, "window_ms", dec.Window.Milliseconds(), win.Milliseconds())
	}
	nonRescue := st.nonRescue
	if !rescue {
		nonRescue++
	}
	// Final promises that no round follows: not while
	// the session's rescue round may still follow a one-way result.
	noRescueLeft := rescue || st.rescueUsed || s.ablate.NoRounds
	final := (dec.Final || nonRescue >= int(s.to.MaxRounds)) && noRescueLeft || k >= maxRound

	seed := st.rng.Uint32()
	cur := roundState{n: k, variant: dec.Variant, name: name, class: class, rescue: rescue, final: final, window: win,
		families: slices.Clone(dec.Families)}
	usable := false
	var ports [2]int
	for r := range 2 {
		sides, active := s.clampSidesLocked(k, r, dec.Sides[r], lim, now)
		usable = usable || active
		rp := protocol.RoundPlan{
			Round:    uint8(k),
			Variant:  name,
			Budget:   class,
			WindowMs: uint16(win / time.Millisecond),
			Final:    final,
			Rescue:   rescue,
			Seed:     seed,
			Sides:    sides,
		}
		rp, clamped := rp.Normalize()
		if clamped {
			s.clampedLocked(k, "plan", 0, 0)
		}
		cur.plans[r] = rp
		for _, fs := range rp.Sides {
			cur.sandwich[r][famIndex(fs.Family)] = fs.Sandwich
			cur.granted[r] += int(fs.MaxPackets)
			ports[r] += int(fs.MaxDistinctPorts)
		}
	}
	if !usable {
		return &terminal{code: protocol.ReasonNoProbeEndpoint}
	}
	for r := range 2 {
		st.granted[r] += cur.granted[r]
		s.c.limiter.grant(s.at(now), r, s.keys[r], cur.granted[r])
	}
	st.recentPorts[k] = ports
	st.cur = cur
	st.lastGranted = class
	if rescue {
		st.rescueUsed = true
	} else {
		st.nonRescue++
	}
	return nil
}

// guardClassLocked applies the escalation guard: the first round
// is at most min(class of Ladder[0], balanced) unless the memory proved the
// promoted variant (then heavy); later rounds rise at most one class above
// the last grant; heavy needs round 2 and random-EDM evidence, else round 3;
// extreme needs AllowExtreme, round 3 and the keys' hourly allowance.
func (s *Session) guardClassLocked(k int, class protocol.BudgetClass, now time.Duration) protocol.BudgetClass {
	st := &s.st
	in := class
	if !class.Valid() {
		class = protocol.BudgetLight
	}
	var ceiling protocol.BudgetClass
	if st.lastGranted == "" {
		ceiling = protocol.BudgetLight
		if len(st.cls.Ladder) > 0 {
			if c, ok := st.cls.Budgets[st.cls.Ladder[0]]; ok && c.Valid() {
				ceiling = c
			}
		}
		ceiling = minClass(ceiling, protocol.BudgetBalanced)
		if st.promoted {
			ceiling = protocol.BudgetHeavy
		}
	} else {
		ceiling = classByRank(st.lastGranted.Rank() + 1)
	}
	// The slow birthday's class runs only in a Background session
	// of a pair found random — by natprobe, or by a one-way round, after
	// which the planner may turn the pair into PDF×RND; there it
	// escapes the escalation guard, first round included: it is wide in
	// time, not in rate, and the strategy memory may start a Background
	// session with it. Elsewhere the round is held to heavy and to the
	// guard.
	background := class == protocol.BudgetBackground && st.mode == protocol.ModeBackground && (st.pairRND || st.sawOneWay())
	if class == protocol.BudgetBackground && !background {
		class = protocol.BudgetHeavy
	}
	if class.Rank() > ceiling.Rank() && !background {
		class = ceiling
	}
	if class == protocol.BudgetHeavy && k < 3 && !(k >= 2 && st.pairRND) && !(st.lastGranted == "" && st.promoted) {
		class = protocol.BudgetBalanced
	}
	if class == protocol.BudgetExtreme &&
		(!s.c.cfg.Budget.AllowExtreme || k < 3 || !s.c.limiter.takeExtreme(s.at(now), s.keys)) {
		class = protocol.BudgetHeavy
	}
	if class != in {
		s.clampedLocked(k, "budget", int64(in.Rank()), int64(class.Rank()))
	}
	return class
}

func minClass(a, b protocol.BudgetClass) protocol.BudgetClass {
	if a.Rank() <= b.Rank() {
		return a
	}
	return b
}

func classByRank(r int) protocol.BudgetClass {
	switch {
	case r <= 1:
		return protocol.BudgetLight
	case r == 2:
		return protocol.BudgetBalanced
	case r == 3:
		return protocol.BudgetHeavy
	}
	return protocol.BudgetExtreme
}

// clampSidesLocked clamps side r's family sides of a round and reports
// whether one of them still sends. A side left without a stage gets a
// reply_only one.
//
// MaxPackets equal to what the stages expand to is the Planner's contract, not
// the clamp's: scaling MaxPackets to the class or the remaining budget, or
// capping an unverified family at 8 × targets, leaves the grant below the
// expansion — the client stops at the grant and the audit reads the grant — and
// admission dropping targets leaves it above, which only charges the key's
// quota a little more.
func (s *Session) clampSidesLocked(k, r int, sides []protocol.FamilySide, lim protocol.ClassLimits, now time.Duration) ([]protocol.FamilySide, bool) {
	st := &s.st
	caps := st.reports[r].Caps
	var out []protocol.FamilySide
	active := false
	for _, fs := range sides {
		if !slices.Contains(st.cls.Families, fs.Family) || len(out) == 2 ||
			slices.ContainsFunc(out, func(o protocol.FamilySide) bool { return o.Family == fs.Family }) {
			s.clampedLocked(k, "sides", int64(len(sides)), int64(len(out)))
			continue
		}
		fs.Stages = slices.Clone(fs.Stages)
		switch fs.Role {
		case protocol.SideSender, protocol.SideReceiver, protocol.SideBoth:
		case protocol.SideReplyOnly:
			fs.Stages = []protocol.Stage{{Kind: protocol.StageReplyOnly}}
		default:
			s.clampedLocked(k, "role", 0, 0)
			continue
		}
		if s.ablate.NoRoleAssign && fs.Role != protocol.SideReplyOnly {
			fs.Role, fs.SendDelayMs = protocol.SideBoth, 0
		}
		fs.SendDelayMs = s.capU16(k, "send_delay_ms", fs.SendDelayMs, maxSendDelayMs)
		sockCap := min(maxSockets, int(lim.MaxSockets), int(s.budget.MaxSockets))
		if caps.MaxSockets > 0 {
			sockCap = min(sockCap, int(caps.MaxSockets))
		}
		fs.Sockets = max(s.capU16(k, "sockets", fs.Sockets, sockCap), 1)
		fs.MaxPPS = s.capU16(k, "max_pps", fs.MaxPPS, min(maxPPS, int(lim.MaxPPS), int(s.budget.MaxPPS)))
		fs.MaxNewPerSec = s.capU16(k, "max_new_per_sec", fs.MaxNewPerSec, min(maxNewPerSec, int(s.budget.MaxNewPerSec)))
		fs.MaxDistinctPorts = s.capU16(k, "max_distinct_ports", fs.MaxDistinctPorts, int(lim.MaxDistinctPorts))
		var sends bool
		var targets int
		fs.Stages, sends, targets = s.clampStagesLocked(k, r, fs.Family, fs.Stages, s.lowTTLOK(caps, fs.Family), now)
		fs.Stages, sends = s.capFreshLocked(k, fs.Stages, sockCap-int(fs.Sockets))
		if !sends {
			fs.Role = protocol.SideReplyOnly
		}
		// The sandwich runs only where both sides took the feature and the
		// family side initiates: its probes bracket the first punch.
		fs.Sandwich = fs.Sandwich && sends && st.sandwich && st.echoed[r] && !s.ablate.NoSandwich
		// A ceiling, not the expansion: a stage the clamp kept whole may now
		// stop at the grant.
		if hi := uint32(unverifiedPerTarget * targets); st.pair.Unverified[fs.Family] && fs.MaxPackets > hi {
			s.clampedLocked(k, "max_packets", int64(fs.MaxPackets), int64(hi))
			fs.MaxPackets = hi
		}
		if len(fs.Stages) == 0 {
			fs.Stages = []protocol.Stage{{Kind: protocol.StageReplyOnly}}
		}
		active = active || sends
		out = append(out, fs)
	}
	if len(out) == 0 {
		fam := protocol.FamilyUDP4
		if len(st.cls.Families) > 0 {
			fam = st.cls.Families[0]
		}
		out = []protocol.FamilySide{{Family: fam, Role: protocol.SideReplyOnly, Sockets: 1,
			Stages: []protocol.Stage{{Kind: protocol.StageReplyOnly}}}}
	}
	// Packets: the class ceiling and the remaining budget (halved after an
	// audit violation), shared by the families.
	limit := min(int(lim.MaxPackets), s.budgetLeftLocked(r, now))
	if st.halve[r] {
		limit /= 2
	}
	total := 0
	for _, fs := range out {
		total += int(fs.MaxPackets)
	}
	if total > limit {
		s.clampedLocked(k, "max_packets", int64(total), int64(limit))
		for i := range out {
			out[i].MaxPackets = uint32(int(out[i].MaxPackets) * limit / total)
		}
	}
	return out, active
}

// lowTTLOK reports whether low-TTL stages are allowed for the side: the
// host can set the TTL for the family and the policy does not forbid it.
func (s *Session) lowTTLOK(caps protocol.ClientCaps, fam protocol.Family) bool {
	if p := s.starts[0].Policy; p.LowTTL != nil && !*p.LowTTL || s.ablate.NoRoleAssign {
		return false
	}
	for _, fc := range caps.Families {
		if fc.Family == fam {
			return fc.LowTTL
		}
	}
	return false
}

// clampStagesLocked clamps the stages of side r for family fam: Direct
// targets pass admission (private targets of a peer on the same LAN or
// behind the same public IP go to their own stage with at most two packets
// each), predict and random stages need a verified peer IP — never in an
// unverified family — and are dropped under the NoPrediction ablation, and
// every count is clamped. An unverified family keeps at most 16 (every
// family unverified: relay-only mode) or 4 distinct public targets. It reports
// whether a stage that sends is left and how many distinct targets the
// stages aim at.
func (s *Session) clampStagesLocked(k, r int, fam protocol.Family, stages []protocol.Stage, ttlOK bool, now time.Duration) ([]protocol.Stage, bool, int) {
	p := 1 - r
	var out []protocol.Stage
	sends := false
	lanLeft, overlayLeft := maxLANTargets, maxOverlay
	unverified := s.st.pair.Unverified[fam]
	pubCap := maxUnverifiedTargets
	if s.st.allUnverified() {
		pubCap = maxRelayOnlyTargets
	}
	var distinct []netip.AddrPort // an unverified family's public targets
	for _, sg := range stages {
		if len(out) >= maxStages {
			s.clampedLocked(k, "stages", int64(len(stages)), maxStages)
			break
		}
		sg.Targets = slices.Clone(sg.Targets)
		sg.Steps = slices.Clone(sg.Steps)
		if sg.TTL != 0 {
			ttl := sg.TTL
			switch {
			case !ttlOK:
				ttl = 0
			case ttl < minTTL:
				ttl = minTTL
			case ttl > maxTTL:
				ttl = maxTTL
			}
			if ttl != sg.TTL {
				s.clampedLocked(k, "ttl", int64(sg.TTL), int64(ttl))
				sg.TTL = ttl
			}
		}
		sg.Repeats = uint8(s.capU16(k, "repeats", uint16(sg.Repeats), maxRepeats))
		switch sg.Kind {
		case protocol.StageDirect:
			var pub, lan []netip.AddrPort
			for _, t := range sg.Targets {
				switch v := s.admitDirectLocked(p, fam, t, k, now); {
				case v == admitPublic && len(pub) < maxTargets:
					if unverified && !slices.Contains(distinct, t) {
						if len(distinct) >= pubCap {
							s.clampedLocked(k, "targets", int64(len(distinct)+1), int64(pubCap))
							continue
						}
						distinct = append(distinct, t)
					}
					pub = append(pub, t)
				case v == admitLAN && lanLeft > 0:
					lan = append(lan, t)
					lanLeft--
				case v == admitOverlay && overlayLeft > 0:
					lan = append(lan, t)
					overlayLeft--
				}
			}
			if len(pub) > 0 {
				d := sg
				d.Targets = pub
				out = append(out, d)
				sends = true
			}
			if len(lan) > 0 && len(out) < maxStages {
				d := sg
				d.Targets, d.Repeats = lan, min(max(sg.Repeats, 1), lanRepeats)
				out = append(out, d)
				sends = true
			}
		case protocol.StageFresh:
			// Fresh sockets aim at the peer's verified endpoints, or pair up
			// with its fresh sockets on its verified IP: a
			// prediction of where the side's own mappings will be, so
			// NoPrediction and an unverified family drop it as they drop
			// predict stages.
			if s.ablate.NoPrediction || unverified || sg.IP.IsValid() && !s.admitIPLocked(p, fam, sg.IP, k, now) {
				s.clampedLocked(k, "stage", 1, 0)
				continue
			}
			var pub []netip.AddrPort
			for _, t := range sg.Targets {
				if s.admitDirectLocked(p, fam, t, k, now) == admitPublic && len(pub) < maxTargets {
					pub = append(pub, t)
				}
			}
			if !sg.IP.IsValid() && len(pub) == 0 {
				continue
			}
			sg.Targets = pub
			sg.Count = s.capU16(k, "count", sg.Count, maxSockets)
			out = append(out, sg)
			sends = true
		case protocol.StageFreshPeer:
			if s.ablate.NoPrediction || unverified || !s.admitIPLocked(p, fam, sg.IP, k, now) {
				s.clampedLocked(k, "stage", 1, 0)
				continue
			}
			sg.Count = s.capU16(k, "count", sg.Count, maxSockets)
			out = append(out, sg)
			sends = true
		case protocol.StagePredict, protocol.StageRandom:
			if s.ablate.NoPrediction || !s.admitIPLocked(p, fam, sg.IP, k, now) {
				s.clampedLocked(k, "stage", 1, 0)
				continue
			}
			sg.Span = s.capU16(k, "span", sg.Span, maxSpan)
			sg.Count = s.capU16(k, "count", sg.Count, maxSpan)
			if len(sg.Steps) > maxSteps {
				sg.Steps = sg.Steps[:maxSteps]
				s.clampedLocked(k, "steps", int64(len(sg.Steps)), maxSteps)
			}
			out = append(out, sg)
			sends = true
		case protocol.StageReplyOnly:
			out = append(out, protocol.Stage{Kind: protocol.StageReplyOnly, AtMs: sg.AtMs})
		default:
			s.clampedLocked(k, "stage", 1, 0)
		}
	}
	return out, sends, len(distinct) + maxLANTargets - lanLeft
}

// capFreshLocked keeps a fresh stage within the sockets left beside the
// side's own: its count is cut to room, and the stage is dropped
// with no room at all. It reports whether a stage that sends is left.
func (s *Session) capFreshLocked(k int, stages []protocol.Stage, room int) ([]protocol.Stage, bool) {
	out := stages[:0]
	sends := false
	for _, st := range stages {
		if st.Kind == protocol.StageFresh {
			if room <= 0 {
				s.clampedLocked(k, "stage", 1, 0)
				continue
			}
			st.Count = s.capU16(k, "fresh_sockets", st.Count, room)
		}
		sends = sends || st.Kind != protocol.StageReplyOnly
		out = append(out, st)
	}
	return out, sends
}

// capU16 clamps v to hi and counts a change.
func (s *Session) capU16(k int, field string, v uint16, hi int) uint16 {
	if int(v) <= hi {
		return v
	}
	s.clampedLocked(k, field, int64(v), int64(hi))
	return uint16(max(hi, 0))
}

// clampedLocked counts one plan change and reports it as an event.
func (s *Session) clampedLocked(k int, field string, from, to int64) {
	s.st.ctr.PlanClamped++
	s.c.emit(Event{Kind: EvPlanClamped, SessionID: s.id, Round: k, Labels: s.labels,
		Data: PlanClampedData{Field: field, From: from, To: to}})
}

// Admission verdicts.
type admitVerdict uint8

const (
	admitRejected admitVerdict = iota
	admitPublic                // a verified IP of the peer
	admitLAN                   // a private address of a peer on the same LAN, or behind the same public IP
	admitOverlay               // an overlay address of a peer that shares an overlay with this side
)

// admitDirectLocked decides whether a Direct target may be sent to side
// 1−p, that is whether a is an address of side p it may aim at
// (admitDirect). Refusals are counted and reported.
func (s *Session) admitDirectLocked(p int, fam protocol.Family, a netip.AddrPort, k int, now time.Duration) admitVerdict {
	v, rule := s.st.admitDirect(p, fam, a)
	if v == admitRejected {
		s.rejectedLocked(k, rule, a, now)
	}
	return v
}

// admitDirect is the admission of a Direct target a of side p, and the rule
// that refused it: its IP is one the peer verified with a cookie (an
// unverified family: one of the global IPs the peer reported), an
// overlay address the peer reported while both sides have some, a
// private address the peer reported while both sides are on one LAN — the
// same public IP alone is not enough — or a private port mapping of the
// peer behind the same public IP (an upstream-LAN candidate).
func (st *sessionState) admitDirect(p int, fam protocol.Family, a netip.AddrPort) (admitVerdict, string) {
	ip := a.Addr()
	switch {
	case !usableAddr(a, fam):
		return admitRejected, "invalid"
	case slices.Contains(st.verified[p][fam], ip):
		return admitPublic, ""
	case st.pair.SharedOverlay[fam] && slices.Contains(st.overlay[p][fam], ip):
		return admitOverlay, ""
	case !isLAN(ip):
		return admitRejected, "unverified"
	case st.pair.LikelySameLAN[fam] && slices.Contains(st.lan[p][fam], ip),
		st.pair.SamePublicIP[fam] && slices.Contains(st.upstream[p][fam], a):
		return admitLAN, ""
	}
	return admitRejected, "not_same_lan"
}

// admitIPLocked decides whether a predict, random or window IP may be aimed
// at: it must be a verified public IP of side p in a verified family.
func (s *Session) admitIPLocked(p int, fam protocol.Family, ip netip.Addr, k int, now time.Duration) bool {
	switch {
	case s.st.pair.Unverified[fam]:
		s.rejectedLocked(k, "unverified_family", netip.AddrPortFrom(ip, 0), now)
		return false
	case fam.Matches(ip) && slices.Contains(s.st.verified[p][fam], ip):
		return true
	}
	s.rejectedLocked(k, "unverified_ip", netip.AddrPortFrom(ip, 0), now)
	return false
}

// admitTargetLocked is admitDirectLocked for one address outside a plan.
func (s *Session) admitTargetLocked(p int, fam protocol.Family, a netip.AddrPort, now time.Duration) bool {
	return s.admitDirectLocked(p, fam, a, s.st.round, now) != admitRejected
}

func (s *Session) rejectedLocked(k int, rule string, a netip.AddrPort, now time.Duration) {
	s.st.ctr.TargetRejected++
	s.c.emit(Event{Kind: EvTargetRejected, At: s.at(now), SessionID: s.id, Round: k, Labels: s.labels,
		Data: TargetRejectedData{Rule: rule, Addr: a}})
}

// usableAddr reports whether a can be a target of family fam at all: a
// unicast address with a port, not unspecified, multicast, broadcast,
// loopback or an IPv6 link-local address without zone — the addresses a
// client never sends to.
func usableAddr(a netip.AddrPort, fam protocol.Family) bool {
	ip := a.Addr()
	switch {
	case !a.IsValid() || a.Port() == 0 || !fam.Matches(ip):
		return false
	case ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return false
	case ip.Is6() && ip.IsLinkLocalUnicast() && ip.Zone() == "":
		return false
	}
	return true
}

// allUnverified reports whether the server verified none of the session's
// families: the relay-only mode, or a registry that observes none of the
// shared families. The planner draws the same line (plan's
// maxRelayOnlyTargets).
func (st *sessionState) allUnverified() bool {
	for _, f := range st.cls.Families {
		if !st.pair.Unverified[f] {
			return false
		}
	}
	return len(st.cls.Families) > 0
}

// isLAN reports whether ip is a private, shared (CGN) or IPv4 link-local
// address: a LAN candidate.
func isLAN(ip netip.Addr) bool {
	return ip.IsPrivate() || nat.IsCGN(ip) || ip.Is4() && ip.IsLinkLocalUnicast()
}

// sawOneWay reports whether a round of the session carried packets one way
// only.
func (st *sessionState) sawOneWay() bool {
	return slices.ContainsFunc(st.records, func(r RoundRecord) bool { return r.Class == RoundOneWay })
}
