package holepunch

import (
	"context"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/controlwire"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/netaddr"
	"github.com/djylb/holepunch/internal/plan"
	"github.com/djylb/holepunch/protocol"
)

// Admission limits.
const (
	maxLANTargets        = 4
	lanPacketsPerRound   = 2
	unverifiedTargets    = 4
	unverifiedPacketsMax = 8
	maxRemapped          = 16 // the server pushes at most 16 drifted mappings a session
	prepareLimit         = 2 * time.Second
	clockSkewWarn        = 300 * time.Second
)

// worker is one family's punching state, built from probe_summary: the
// peer's verified and admissible addresses and this side's capabilities.
// It is read-only after the summary, except for the atomics: the peer's
// mappings the server verified later (remapped) and two capability flags.
type worker struct {
	fam        protocol.Family
	fs         *famState
	self, peer protocol.FamilyView
	verified   map[netip.Addr]bool // peer IPs the server verified by cookie
	endpoints  map[netip.AddrPort]bool
	// remapped are the peer's mappings the server verified while punching
	// and pushed as peer_targets{source: drift}, copy-on-write: their
	// IPs are admitted like verified ones from then on.
	remapped atomic.Pointer[[]netip.AddrPort]
	// selfMapped are this side's primary-socket mappings the server
	// verified, from the summary's self view: a re-observed mapping among
	// them is no news.
	selfMapped []netip.AddrPort
	lan        map[netip.Addr]bool     // the peer's LAN addresses, kept only when both sides share a LAN
	overlay    map[netip.Addr]bool     // the peer's overlay addresses, kept only when both sides have some
	portmap    map[netip.AddrPort]bool // the peer's port-mapping endpoints of the summary: their paths are portmap paths
	reported   map[netip.Addr]bool     // unverified family: the peer's self-reported global addresses
	unverified bool                    // the server could not verify this family's endpoints
	samePublic bool                    // both sides leave through the same public IP
	allow      map[uint16]struct{}     // the peer's observed ports, exempt from the sensitive-port filter
	lowTTL     bool
	lowTTLOff  atomic.Bool // a socket refused a low TTL: warned once
	hairpinOK  atomic.Bool // the hairpin self-test succeeded: the public path loops back
	primary    *udpSock
	selfTraits protocol.Traits
	peerTraits protocol.Traits
}

// admit is the client side of target admission: an initiated packet may go only
// to a verified peer IP, to the peer's LAN address when both sides share a LAN
// or its overlay address when both sides have one (direct only, at most two
// packets per round), or, in a family the server could not verify, to the
// peer's self-reported global addresses (direct only, at most eight packets per
// round). Special addresses never pass, nor do this host's own addresses unless
// the peer runs on this host (sameHost); a private verified address is a direct
// target only; a low or sensitive port only when it is exactly a known peer
// endpoint.
func (w *worker) admit(rt *runtime, ap netip.AddrPort, kind protocol.StageKind) (ok bool, perTarget int) {
	ap = netaddr.Canon(ap)
	a := ap.Addr()
	if !w.fam.Matches(a) || netaddr.Unusable(a) || ap.Port() == 0 || rt.isLocal(a) && !w.sameHost(rt, ap, kind) {
		return false, 0
	}
	if kind == protocol.StageDirect && (ap.Port() < 1024 || plan.SensitivePort(ap.Port())) && !w.endpoints[ap] && !w.isRemapped(ap) {
		return false, 0
	}
	switch {
	case w.verifiedIP(a):
		if netaddr.Private(a) && kind != protocol.StageDirect {
			return false, 0
		}
		return true, 0
	case (w.lan[a] || w.overlay[a]) && kind == protocol.StageDirect:
		return true, lanPacketsPerRound
	case w.unverified && w.reported[a] && kind == protocol.StageDirect:
		return true, unverifiedPacketsMax
	}
	return false, 0
}

// verifiedIP reports whether the server verified a as an IP of the peer: in
// the summary, or later as the IP of a pushed drifted mapping.
func (w *worker) verifiedIP(a netip.Addr) bool {
	if w.verified[a] {
		return true
	}
	if list := w.remapped.Load(); list != nil {
		return slices.ContainsFunc(*list, func(m netip.AddrPort) bool { return m.Addr() == a })
	}
	return false
}

// isRemapped reports whether ap is one of the peer's pushed drifted
// mappings: like a summary endpoint, it is exempt from the low and
// sensitive port filter.
func (w *worker) isRemapped(ap netip.AddrPort) bool {
	list := w.remapped.Load()
	return list != nil && slices.Contains(*list, ap)
}

// adoptRemap records a mapping of the peer that the server verified while
// punching and pushed as peer_targets{source: drift}: the server
// observed it in natprobe and the peer echoed its cookie, as for the
// summary's endpoints. A new IP is taken only when it is global and not
// private; a drifted port on an IP the summary verified is taken as it is.
// At most maxRemapped are kept.
func (w *worker) adoptRemap(ap netip.AddrPort) {
	a := ap.Addr()
	if !w.verified[a] && (!a.IsGlobalUnicast() || netaddr.Private(a)) {
		return
	}
	for {
		cur := w.remapped.Load()
		var list []netip.AddrPort
		if cur != nil {
			list = *cur
		}
		if len(list) >= maxRemapped || slices.Contains(list, ap) {
			return
		}
		next := append(slices.Clip(list), ap)
		if w.remapped.CompareAndSwap(cur, &next) {
			return
		}
	}
}

// sameHost reports whether a target on one of this host's addresses is the
// peer itself, running on this host: a LAN
// address of the peer, a Direct target, at a port no socket of this session
// holds. The port rule and the role check keep the session from punching
// itself.
func (w *worker) sameHost(rt *runtime, ap netip.AddrPort, kind protocol.StageKind) bool {
	return kind == protocol.StageDirect && w.lan[ap.Addr()] && !rt.socks.ownsPort(w.fam, ap.Port())
}

// isLocal reports whether a is one of this host's addresses.
func (rt *runtime) isLocal(a netip.Addr) bool {
	_, ok := rt.localIPs[a]
	return ok
}

func newWorker(rt *runtime, fs *famState, sum *protocol.ProbeSummary) *worker {
	w := &worker{
		fam: fs.fam, fs: fs, primary: fs.primary,
		verified: map[netip.Addr]bool{}, endpoints: map[netip.AddrPort]bool{},
		lan: map[netip.Addr]bool{}, overlay: map[netip.Addr]bool{}, portmap: map[netip.AddrPort]bool{},
		reported: map[netip.Addr]bool{}, allow: map[uint16]struct{}{},
		unverified: sum.Pair.Unverified[fs.fam],
		samePublic: sum.Pair.SamePublicIP[fs.fam],
		lowTTL:     rt.lowTTLCapable(fs) && !rt.abl.NoRoleAssign,
	}
	for _, v := range sum.Self.Families {
		if v.Family == fs.fam {
			w.self, w.selfTraits = v, v.Traits
		}
	}
	for _, e := range w.self.Endpoints {
		if e.Verified && e.Source == protocol.EndpointServer && e.Socket == fs.primary.id {
			w.selfMapped = append(w.selfMapped, netaddr.Canon(e.Addr))
		}
	}
	for _, v := range sum.Peer.Families {
		if v.Family == fs.fam {
			w.peer, w.peerTraits = v, v.Traits
		}
	}
	sameLAN := sum.Pair.LikelySameLAN[fs.fam]
	overlay := sum.Pair.SharedOverlay[fs.fam] && !rt.opts.ExcludeOverlay
	for _, e := range w.peer.Endpoints {
		ap := netaddr.Canon(e.Addr)
		w.endpoints[ap] = true
		a := ap.Addr()
		if e.Source == protocol.EndpointPortmap {
			w.portmap[ap] = true
		}
		switch {
		case e.Source == protocol.EndpointOverlay:
			if overlay && len(w.overlay) < maxOverlayAddrs {
				w.overlay[a] = true
			}
		case e.Verified:
			w.verified[a] = true
			w.allow[ap.Port()] = struct{}{}
		case e.Source == protocol.EndpointLAN && sameLAN && len(w.lan) < maxLANTargets && netaddr.Private(a):
			w.lan[a] = true
		case w.unverified && a.IsGlobalUnicast() && !netaddr.Private(a) && len(w.reported) < unverifiedTargets:
			w.reported[a] = true
		}
	}
	return w
}

// admitUpstream admits a port-mapping address of the peer's own router that
// lies in the network both sides share upstream (a private or 100.64
// external address, peer_targets{source: portmap}): only when both
// sides leave through the same public IP, direct only, at most two packets
// per round.
func (w *worker) admitUpstream(rt *runtime, ap netip.AddrPort) bool {
	ap = netaddr.Canon(ap)
	a := ap.Addr()
	return w.samePublic && w.fam.Matches(a) && netaddr.Private(a) && !netaddr.Unusable(a) &&
		ap.Port() >= 1024 && !plan.SensitivePort(ap.Port()) && !rt.isLocal(a)
}

// prepare handles probe_summary, from the summary wait to the go wait: it
// applies the tighter timeouts
// and the session budget, builds a worker per shared family, pre-binds the
// first round's sockets, admits its targets and writes punch_ready — or
// punch_result{no_common_family} when no family is left.
func (rt *runtime) prepare(sum stamped[protocol.ProbeSummary]) error {
	s, clamped := sum.msg.Normalize()
	rt.summary, rt.summaryAt = s, sum.at
	rt.timing.summaryWait = sum.at.Sub(rt.startAt) - rt.timing.probe
	rt.timeouts = s.Timeouts.Within(rt.start.Timeouts)
	rt.computeWaits()
	rt.transport = s.Transport
	var startBudget, localBudget protocol.Budget
	if rt.start.Policy != nil {
		startBudget = rt.start.Policy.Budget
	}
	if rt.opts.Policy != nil {
		localBudget = rt.opts.Policy.Budget
	}
	rt.sessBudget = protocol.TightenBudget(startBudget, s.Plan.Budget, localBudget)
	rt.sender.setBudget(rt.sessBudget)
	rt.socks.setLimit(int(rt.sessBudget.MaxSockets))
	rt.phases.note(stageSummaryReceived)
	rt.progress(progressEvent{stage: stageSummaryReceived, status: protocol.StatusInfo})

	for _, f := range s.Pair.SharedFamilies {
		if s.Pair.Unverified[f] {
			rt.addWarn(protocol.WarnUnverifiedTargets)
		}
	}
	if off := s.Pair.ClockOffsetMs[rt.role]; time.Duration(abs64(off))*time.Millisecond > clockSkewWarn {
		rt.addWarn(protocol.WarnClockSkew)
	}
	for _, f := range s.Pair.SharedFamilies {
		fs := rt.fam(f)
		if fs.primary == nil || !(fs.probed || s.Pair.Unverified[f]) {
			continue
		}
		fs.worker = newWorker(rt, fs, &s)
		rt.workers = append(rt.workers, fs.worker)
	}
	if len(rt.workers) == 0 {
		return fail(protocol.ReasonNoCommonFamily, "", nil)
	}

	r1, normalized := cloneRound(s.Plan.Round1).Normalize()
	r1, tightened := r1.ClampTo(rt.sessBudget)
	clamped = clamped || normalized || tightened
	rt.pg = life.New(rt.g.Context())
	rt.startPunching()

	var fams []protocol.FamilyReady
	for _, side := range r1.Sides {
		w := rt.fam(side.Family).worker
		if w == nil {
			continue
		}
		rejected := rt.countRejected(w, side)
		socks, _ := rt.socks.roundSockets(rt.g.Context(), w.primary, socketsBeforeFiring(side), roundPurpose(side))
		fr := protocol.FamilyReady{Family: side.Family, Sockets: uint16(len(socks)), Clamped: clamped, Rejected: uint16(min(rejected, 0xFFFF))}
		if w.fs.mapping != nil {
			fr.PortMap = w.fs.mapping.takeReport()
		}
		fams = append(fams, fr)
	}
	if len(fams) == 0 {
		return fail(protocol.ReasonNoCommonFamily, "round1", nil)
	}
	for _, w := range rt.workers {
		if s.Pair.SamePublicIP[w.fam] && w.fs.prober.Load() != nil {
			rt.startHairpin(w)
		}
	}
	now := rt.clk.Now()
	if now.Sub(sum.at) > prepareLimit {
		return fail(protocol.ReasonInternal, "prepare_timeout", nil)
	}
	for _, w := range rt.workers {
		rt.phases.advanceFamily(w.fam, protocol.PhasePlanned, "summary_received", now)
	}
	summaryAt := sum.at
	ready := protocol.PunchReady{SessionID: rt.start.SessionID, Role: rt.role, Families: fams}
	if err := rt.ctl.sendBuilt(controlwire.TypePunchReady, func(at time.Time) protocol.Message {
		r := ready
		r.ElapsedMs = elapsedMs(summaryAt, at)
		return r
	}); err != nil {
		return rt.ctl.sendFailure("punch_ready", err)
	}
	rt.readyAt = rt.clk.Now()
	rt.phases.advance(protocol.PhaseReady, stageReadySent, rt.readyAt)
	rt.progress(progressEvent{stage: stageReadySent, status: protocol.StatusInfo})
	return nil
}

// countRejected counts the targets of a side that admission refuses.
func (rt *runtime) countRejected(w *worker, side protocol.FamilySide) int {
	n := 0
	for _, st := range side.Stages {
		switch st.Kind {
		case protocol.StageDirect:
			for _, t := range st.Targets {
				if ok, _ := w.admit(rt, t, st.Kind); !ok {
					n++
				}
			}
		case protocol.StagePredict, protocol.StageRandom, protocol.StageFreshPeer:
			if ok, _ := w.admit(rt, netip.AddrPortFrom(st.IP, 1024), st.Kind); !ok {
				n++
			}
		case protocol.StageFresh:
			for _, t := range st.Targets {
				if ok, _ := w.admit(rt, t, protocol.StageDirect); !ok {
					n++
				}
			}
			if ok, _ := w.admit(rt, netip.AddrPortFrom(st.IP, 1024), st.Kind); st.IP.IsValid() && !ok {
				n++
			}
		}
	}
	return n
}

// roundPurpose names the extra sockets of a side: warmup when they pre-open
// mappings with a low TTL, birthday otherwise.
func roundPurpose(side protocol.FamilySide) string {
	for _, st := range side.Stages {
		if st.TTL > 0 {
			return PurposeWarmup
		}
	}
	return PurposeBirthday
}

// sandwichOK reports whether this session negotiated the sandwich feature
// and may run it.
func (rt *runtime) sandwichOK() bool {
	if rt.abl.NoSandwich {
		return false
	}
	for _, f := range rt.features {
		if f == protocol.FeatureSandwich {
			return true
		}
	}
	return false
}

// startHairpin runs the hairpin self-test of a family behind the same public
// IP as its peer. It runs in the punching group, so the handover
// ends it before the winning socket changes hands.
func (rt *runtime) startHairpin(w *worker) {
	pr := w.fs.prober.Load()
	rt.pg.Go("hairpin:"+string(w.fam), func(ctx context.Context) {
		v := pr.Hairpin(ctx)
		w.hairpinOK.Store(v == protocol.TriTrue)
		status := protocol.StatusOK
		if v != protocol.TriTrue {
			status = protocol.StatusFail
		}
		rt.progress(progressEvent{stage: stageHairpinResult, status: status, detail: v.String(), family: w.fam})
	})
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}
