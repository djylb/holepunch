package coord

import (
	"net/netip"
	"slices"
	"time"

	"github.com/djylb/holepunch/protocol"
)

// sideClamp is what the clamp of one side's round takes from the session
// besides the admission sets and the audit.
type sideClamp struct {
	k, r       int // the round and the side
	now        time.Duration
	lim        protocol.ClassLimits // the round's class
	families   []protocol.Family    // the classification's
	caps       protocol.ClientCaps  // the side's
	sandwich   bool                 // negotiated, and the side accepted the feature
	relayOnly  bool                 // protocol.RelayOnly
	budgetLeft int                  // budgetLeftLocked
}

// clampSidesLocked clamps side c.r's family sides of round c.k and reports
// whether one of them still sends. A side left without a stage gets a
// reply_only one.
//
// MaxPackets equal to what the stages expand to is the Planner's contract, not
// the clamp's: scaling MaxPackets to the class or the remaining budget, or
// capping an unverified family at 8 × targets, leaves the grant below the
// expansion — the client stops at the grant and the audit reads the grant — and
// admission dropping targets leaves it above, which only charges the key's
// quota a little more.
func (s *Session) clampSidesLocked(c sideClamp, sides []protocol.FamilySide) ([]protocol.FamilySide, bool) {
	k, r, lim, caps := c.k, c.r, c.lim, c.caps
	var out []protocol.FamilySide
	active := false
	for _, fs := range sides {
		if !slices.Contains(c.families, fs.Family) || len(out) == 2 ||
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
		fs.SendDelayMs = s.capU16(k, "send_delay_ms", fs.SendDelayMs, protocol.MaxSendDelayMs)
		sockCap := min(protocol.MaxSideSockets, int(lim.MaxSockets), int(s.budget.MaxSockets))
		if caps.MaxSockets > 0 {
			sockCap = min(sockCap, int(caps.MaxSockets))
		}
		fs.Sockets = max(s.capU16(k, "sockets", fs.Sockets, sockCap), 1)
		fs.MaxPPS = s.capU16(k, "max_pps", fs.MaxPPS, min(int(protocol.CeilingBudget().MaxPPS), int(lim.MaxPPS), int(s.budget.MaxPPS)))
		fs.MaxNewPerSec = s.capU16(k, "max_new_per_sec", fs.MaxNewPerSec, min(int(protocol.CeilingBudget().MaxNewPerSec), int(s.budget.MaxNewPerSec)))
		fs.MaxDistinctPorts = s.capU16(k, "max_distinct_ports", fs.MaxDistinctPorts, int(lim.MaxDistinctPorts))
		var targets int
		// capFreshLocked reports, over the stages it keeps, whether one sends.
		fs.Stages, _, targets = s.clampStagesLocked(c, fs.Family, fs.Stages, s.lowTTLOK(caps, fs.Family))
		var sends bool
		fs.Stages, sends = s.capFreshLocked(k, fs.Stages, sockCap-int(fs.Sockets))
		if !sends {
			fs.Role = protocol.SideReplyOnly
		}
		// The sandwich runs only where both sides took the feature and the
		// family side initiates: its probes bracket the first punch.
		fs.Sandwich = fs.Sandwich && sends && c.sandwich && !s.ablate.NoSandwich
		// A ceiling, not the expansion: a stage the clamp kept whole may now
		// stop at the grant.
		if hi := uint32(protocol.UnverifiedRepeats * targets); s.st.adm.pair.Unverified[fs.Family] && fs.MaxPackets > hi {
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
		if len(c.families) > 0 {
			fam = c.families[0]
		}
		out = []protocol.FamilySide{{Family: fam, Role: protocol.SideReplyOnly, Sockets: 1,
			Stages: []protocol.Stage{{Kind: protocol.StageReplyOnly}}}}
	}
	// Packets: the class ceiling and the remaining budget (halved after an
	// audit violation), shared by the families.
	limit := min(int(lim.MaxPackets), c.budgetLeft)
	if s.st.audit.halve[r] {
		limit /= 2
	}
	// In 64 bits: the planner's MaxPackets may be anything a uint32 holds.
	var total uint64
	for _, fs := range out {
		total += uint64(fs.MaxPackets)
	}
	if total > uint64(limit) {
		s.clampedLocked(k, "max_packets", int64(total), int64(limit))
		for i := range out {
			out[i].MaxPackets = uint32(uint64(out[i].MaxPackets) * uint64(limit) / total)
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

// clampStagesLocked clamps the stages of side c.r for family fam: Direct
// targets pass admission (private targets of a peer on the same LAN or
// behind the same public IP go to their own stage with at most two packets
// each), predict and random stages need a verified peer IP — never in an
// unverified family — and are dropped under the NoPrediction ablation, and
// every count is clamped. An unverified family keeps at most 16 (every
// family unverified: NoObserver mode) or 4 distinct public targets. It reports
// whether a stage that sends is left and how many distinct targets the
// stages aim at.
func (s *Session) clampStagesLocked(c sideClamp, fam protocol.Family, stages []protocol.Stage, ttlOK bool) ([]protocol.Stage, bool, int) {
	k, p, now := c.k, 1-c.r, c.now
	var out []protocol.Stage
	sends := false
	lanLeft, overlayLeft := protocol.MaxLANTargets, protocol.MaxOverlayTargets
	unverified := s.st.adm.pair.Unverified[fam]
	pubCap := protocol.MaxUnverifiedTargets
	if c.relayOnly {
		pubCap = protocol.MaxRelayOnlyTargets
	}
	var distinct []netip.AddrPort // an unverified family's public targets
	for _, sg := range stages {
		if len(out) >= protocol.MaxStages {
			s.clampedLocked(k, "stages", int64(len(stages)), protocol.MaxStages)
			break
		}
		sg = sg.Clone()
		if sg.TTL != 0 {
			ttl := sg.TTL
			switch {
			case !ttlOK:
				ttl = 0
			case ttl < protocol.MinLowTTL:
				ttl = protocol.MinLowTTL
			case ttl > protocol.MaxLowTTL:
				ttl = protocol.MaxLowTTL
			}
			if ttl != sg.TTL {
				s.clampedLocked(k, "ttl", int64(sg.TTL), int64(ttl))
				sg.TTL = ttl
			}
		}
		sg.Repeats = uint8(s.capU16(k, "repeats", uint16(sg.Repeats), protocol.MaxRepeats))
		switch sg.Kind {
		case protocol.StageDirect:
			var pub, lan []netip.AddrPort
			for _, t := range sg.Targets {
				switch v := s.admitDirectLocked(p, fam, t, k, now); {
				case v == admitPublic && len(pub) < protocol.MaxStageTargets:
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
			if len(lan) > 0 && len(out) < protocol.MaxStages {
				d := sg
				d.Targets, d.Repeats = lan, min(max(sg.Repeats, 1), protocol.LANRepeats)
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
				if s.admitDirectLocked(p, fam, t, k, now) == admitPublic && len(pub) < protocol.MaxStageTargets {
					pub = append(pub, t)
				}
			}
			if !sg.IP.IsValid() && len(pub) == 0 {
				continue
			}
			sg.Targets = pub
			sg.Count = s.capU16(k, "count", sg.Count, protocol.MaxSideSockets)
			out = append(out, sg)
			sends = true
		case protocol.StageFreshPeer:
			if s.ablate.NoPrediction || unverified || !s.admitIPLocked(p, fam, sg.IP, k, now) {
				s.clampedLocked(k, "stage", 1, 0)
				continue
			}
			sg.Count = s.capU16(k, "count", sg.Count, protocol.MaxSideSockets)
			out = append(out, sg)
			sends = true
		case protocol.StagePredict, protocol.StageRandom:
			if s.ablate.NoPrediction || !s.admitIPLocked(p, fam, sg.IP, k, now) {
				s.clampedLocked(k, "stage", 1, 0)
				continue
			}
			sg.Span = s.capU16(k, "span", sg.Span, protocol.MaxSpanCount)
			sg.Count = s.capU16(k, "count", sg.Count, protocol.MaxSpanCount)
			if len(sg.Steps) > protocol.MaxSteps {
				sg.Steps = sg.Steps[:protocol.MaxSteps]
				s.clampedLocked(k, "steps", int64(len(sg.Steps)), protocol.MaxSteps)
			}
			out = append(out, sg)
			sends = true
		case protocol.StageReplyOnly:
			out = append(out, protocol.Stage{Kind: protocol.StageReplyOnly, AtMs: sg.AtMs})
		default:
			s.clampedLocked(k, "stage", 1, 0)
		}
	}
	return out, sends, len(distinct) + protocol.MaxLANTargets - lanLeft + protocol.MaxOverlayTargets - overlayLeft
}

// capFreshLocked keeps a fresh stage within the sockets left beside the
// side's own: its count is cut to room, and the stage is dropped
// with no room at all. It reports whether a stage that sends is left.
func (s *Session) capFreshLocked(k int, stages []protocol.Stage, room int) ([]protocol.Stage, bool) {
	out := stages[:0]
	sends := false
	for _, sg := range stages {
		if sg.Kind == protocol.StageFresh {
			if room <= 0 {
				s.clampedLocked(k, "stage", 1, 0)
				continue
			}
			sg.Count = s.capU16(k, "fresh_sockets", sg.Count, room)
		}
		sends = sends || sg.Kind != protocol.StageReplyOnly
		out = append(out, sg)
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

// admitDirectLocked decides whether a Direct target may be sent to side
// 1−p, that is whether a is an address of side p it may aim at
// (admitDirect). Refusals are counted and reported.
func (s *Session) admitDirectLocked(p int, fam protocol.Family, a netip.AddrPort, k int, now time.Duration) admitVerdict {
	v, rule := s.st.adm.admitDirect(p, fam, a)
	if v == admitRejected {
		s.rejectedLocked(k, rule, a, now)
	}
	return v
}

// admitIPLocked decides whether a predict, random, fresh or window IP of
// side p may be aimed at (admitIP). Refusals are counted and reported.
func (s *Session) admitIPLocked(p int, fam protocol.Family, ip netip.Addr, k int, now time.Duration) bool {
	ok, rule := s.st.adm.admitIP(p, fam, ip)
	if !ok {
		s.rejectedLocked(k, rule, netip.AddrPortFrom(ip, 0), now)
	}
	return ok
}
