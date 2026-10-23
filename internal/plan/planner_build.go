package plan

import (
	"cmp"
	"net/netip"
	"slices"
	"time"

	"github.com/djylb/holepunch/internal/netaddr"
	"github.com/djylb/holepunch/protocol"
)

// This file turns the chosen variants and the merged peer views into
// concrete protocol.FamilySide values. Every family's side gets the class of
// its own variant; the round's class bounds what the families share — the
// sockets, the packets and the new-target bucket of each side —
// and the packet invariant holds exactly: a side's MaxPackets is the number of
// packets its stages expand to (Direct: sockets × targets × repeats; the LAN
// stage: targets × repeats on the primary socket; predict and random: span
// and count), so the sender never stops a planned stage on its budget.
//
// Every target is one the client admits: a
// verified IP of the peer; in an unverified family one of the first four
// global unicast addresses the peer reported; the peer's private LAN
// address when both sides share a LAN; the peer's overlay address when both
// sides reported some. Upstream-LAN candidates (private
// port mappings) are not plan targets: the client admits them only from
// peer_targets{source: portmap}, which the coordinator sends.

// Target limits.
const (
	maxDirectTargets = 8 // Direct targets of a side and round
	guessRepeats     = 2 // packets per local-port guess and socket (D(2))
)

// ---- view helpers ----

func sharedFamilies(a, b protocol.PeerView) []protocol.Family {
	var out []protocol.Family
	for _, f := range []protocol.Family{protocol.FamilyUDP6, protocol.FamilyUDP4} {
		fa, oka := findFamily(a, f)
		fb, okb := findFamily(b, f)
		if oka && okb && CategoryOf(fa.Traits) != CatNone && CategoryOf(fb.Traits) != CatNone {
			out = append(out, f)
		}
	}
	return out
}

func findFamily(v protocol.PeerView, f protocol.Family) (protocol.FamilyView, bool) {
	for _, fv := range v.Families {
		if fv.Family == f {
			return fv, true
		}
	}
	return protocol.FamilyView{}, false
}

func familyTraits(v protocol.PeerView, f protocol.Family) protocol.Traits {
	if fv, ok := findFamily(v, f); ok {
		return fv.Traits
	}
	return protocol.Traits{}
}

// canonicalSideA picks the A (rule) side: the lower-rank category, ties broken
// by the lexicographically smaller observed address, then by role.
func canonicalSideA(catI, catR Category, iTr, rTr protocol.Traits) protocol.Role {
	switch {
	case catI.rank() < catR.rank():
		return protocol.RoleInitiator
	case catR.rank() < catI.rank():
		return protocol.RoleResponder
	}
	if iTr.Observed.String() <= rTr.Observed.String() {
		return protocol.RoleInitiator
	}
	return protocol.RoleResponder
}

func lowTTLEnabled(p protocol.Policy) bool { return p.LowTTL == nil || *p.LowTTL }

// peerAddrs is what a side may aim at in one family of its peer.
type peerAddrs struct {
	direct  []netip.AddrPort // public Direct targets
	public  []netip.Addr     // the IPs the client admits Direct targets on: verified, or reported in an unverified family
	lan     []netip.AddrPort // the peer's LAN endpoints, when both share a LAN
	lanIPs  []netip.Addr     // the IPs the client admits LAN targets on
	overlay []netip.AddrPort // the peer's overlay endpoints, when both sides have some
	// guess is the peer's primary socket at its local port on the verified
	// IP (EndpointLocalPort), when the Direct targets lack it.
	guess   []netip.AddrPort
	sprayIP netip.Addr // the verified public IP predict and random stages aim at; invalid for none
}

// peerAddrsOf returns the targets of family fp in the peer's view fv. It
// mirrors how the client admits them (the root package's newWorker and
// admit): an endpoint is one of the peer's first two
// overlay endpoints when both sides have an overlay, a verified
// address of the peer, or else, on a shared LAN, one of the first four
// distinct private IPs among its LAN endpoints, or else, in an unverified
// family, one of the first four distinct global unicast IPs it reported.
func peerAddrsOf(fp familyPlan, fv protocol.FamilyView) peerAddrs {
	var pa peerAddrs
	var verified, reported []netip.Addr
	for _, e := range fv.Endpoints {
		ip := e.Addr.Addr().Unmap().WithZone("")
		switch {
		case e.Source == protocol.EndpointOverlay:
			if fp.SharedOverlay && netaddr.UsableTarget(e.Addr) && len(pa.overlay) < protocol.MaxOverlayTargets && !slices.Contains(pa.overlay, e.Addr) {
				pa.overlay = append(pa.overlay, e.Addr)
			}
		case e.Verified:
			if !slices.Contains(verified, ip) {
				verified = append(verified, ip)
			}
		case fp.SameLAN && e.Source == protocol.EndpointLAN && netaddr.Private(ip) && len(pa.lanIPs) < protocol.MaxLANTargets:
			if !slices.Contains(pa.lanIPs, ip) {
				pa.lanIPs = append(pa.lanIPs, ip)
			}
		case fp.Unverified && netaddr.Public(ip) && len(reported) < protocol.MaxReportedIPs:
			if !slices.Contains(reported, ip) {
				reported = append(reported, ip)
			}
		}
	}
	pa.public = slices.Concat(verified, reported)
	if fp.Unverified {
		pa.direct = reportedTargets(fv, pa.public, fp.MaxTargets)
	} else {
		pa.direct = directTargets(fv)
		pa.guess = guessTargets(fv, pa.direct)
		pa.sprayIP = sprayIP(pa.direct, fv)
	}
	if fp.SameLAN {
		pa.lan = lanTargets(fv, pa.lanIPs, verified)
	}
	return pa
}

// directTargets returns the Direct targets toward a verified peer family:
// the mappings the peer can answer on, at most maxDirectTargets. A
// MultiExit peer gets one verified endpoint per exit IP. Otherwise the
// targets are the first verified mapping of the peer's primary socket and of
// its second socket, on the primary IP: the peer punches from its primary
// socket, a socket's later mappings are toward other servers, and an
// endpoint-dependent NAT creates a new mapping toward us anyway, so the
// ladder's "D(n) to observed" means one target per probing socket. Sibling
// sockets do not punch and are left out. The mappings
// third-party STUN servers saw of the primary socket on the same IP at
// other ports follow: a NAT that maps the server's address apart
// from the rest shows the server one mapping and everybody else another,
// so they are server-reflexive candidates of their own. The client admits
// them by the verified IP, as any Direct target.
func directTargets(fv protocol.FamilyView) []netip.AddrPort {
	var out []netip.AddrPort
	var primary netip.Addr
	var server, second bool
	for _, e := range fv.Endpoints {
		if !e.Verified || !netaddr.UsableTarget(e.Addr) || len(out) == maxDirectTargets {
			continue
		}
		if fv.Traits.MultiExit {
			if !containsIP(out, e.Addr.Addr()) {
				out = append(out, e.Addr)
			}
			continue
		}
		if !primary.IsValid() {
			primary = e.Addr.Addr()
		}
		switch {
		case e.Addr.Addr() != primary:
		case e.Source == protocol.EndpointServer && !server:
			server = true
			out = append(out, e.Addr)
		case e.Source == protocol.EndpointSecond && !second:
			second = true
			out = append(out, e.Addr)
		}
	}
	if !primary.IsValid() || fv.Traits.MultiExit {
		return out
	}
	for _, e := range fv.Endpoints {
		if e.Source == protocol.EndpointSTUN && e.Addr.Addr() == primary && netaddr.UsableTarget(e.Addr) &&
			len(out) < maxDirectTargets && !slices.Contains(out, e.Addr) {
			out = append(out, e.Addr)
		}
	}
	return out
}

// guessTargets returns the peer's local-port candidate (EndpointLocalPort)
// on the IP of its first Direct target, unless a Direct target
// holds it already: a NAT that keeps the local port on the path toward us
// maps the peer's primary socket there although natprobe saw another
// port. A MultiExit peer has no single IP to put it on.
func guessTargets(fv protocol.FamilyView, direct []netip.AddrPort) []netip.AddrPort {
	if len(direct) == 0 || fv.Traits.MultiExit {
		return nil
	}
	for _, e := range fv.Endpoints {
		if e.Source == protocol.EndpointLocalPort && e.Addr.Addr() == direct[0].Addr() && netaddr.UsableTarget(e.Addr) && !slices.Contains(direct, e.Addr) {
			return []netip.AddrPort{e.Addr}
		}
	}
	return nil
}

// seenTargets returns the peer's sources role heard in family fp's earlier
// rounds (Evidence.SeenFrom) on an IP the client admits Direct targets on: the
// peer's real mappings toward this side. Once there are any, every later round
// aims at them instead of what natprobe and STUN observed. At most
// fp.MaxTargets.
func seenTargets(in input, fp familyPlan, role int, pa peerAddrs) []netip.AddrPort {
	var out []netip.AddrPort
	for _, a := range in.Evidence.SeenFrom[role] {
		ip := a.Addr().Unmap()
		if len(out) < fp.MaxTargets && protocol.FamilyOf(ip) == fp.Family && netaddr.UsableTarget(a) && slices.Contains(pa.public, ip) &&
			!netaddr.Private(ip) && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

// reportedTargets returns the Direct targets toward a peer family in the
// unverified mode: the peer's endpoints on the admitted IPs — verified ones,
// where only the other side is LAN-observed (Traits.LANObserved), and the
// global addresses it reported — in the order of its view, at most limit.
func reportedTargets(fv protocol.FamilyView, ips []netip.Addr, limit int) []netip.AddrPort {
	var out []netip.AddrPort
	for _, e := range fv.Endpoints {
		if len(out) == limit {
			break
		}
		if e.Source != protocol.EndpointOverlay && netaddr.UsableTarget(e.Addr) && slices.Contains(ips, e.Addr.Addr().Unmap()) && !slices.Contains(out, e.Addr) {
			out = append(out, e.Addr)
		}
	}
	return out
}

// lanTargets returns the peer's LAN endpoints on the admitted LAN IPs, at
// most protocol.MaxLANTargets. An IP that is also verified is left
// out: the client treats it as a verified address, which the public Direct
// stage already covers.
func lanTargets(fv protocol.FamilyView, lanIPs, verified []netip.Addr) []netip.AddrPort {
	var out []netip.AddrPort
	for _, e := range fv.Endpoints {
		if len(out) == protocol.MaxLANTargets {
			break
		}
		ip := e.Addr.Addr().Unmap()
		if e.Source == protocol.EndpointLAN && !e.Verified && netaddr.UsableTarget(e.Addr) && slices.Contains(lanIPs, ip) &&
			!slices.Contains(verified, ip) && !slices.Contains(out, e.Addr) {
			out = append(out, e.Addr)
		}
	}
	return out
}

// sprayIP is the IP predict and random stages aim at: the first public IP
// among the Direct targets, or else the verified observed one. The client
// never sprays a private IP, verified or not.
func sprayIP(targets []netip.AddrPort, fv protocol.FamilyView) netip.Addr {
	for _, t := range targets {
		if ip := t.Addr().Unmap(); !netaddr.Private(ip) {
			return ip
		}
	}
	obs := fv.Traits.Observed.Addr().Unmap()
	for _, e := range fv.Endpoints {
		if e.Verified && e.Addr.Addr().Unmap() == obs && netaddr.Public(obs) {
			return obs
		}
	}
	return netip.Addr{}
}

func containsIP(s []netip.AddrPort, ip netip.Addr) bool {
	for _, a := range s {
		if a.Addr() == ip {
			return true
		}
	}
	return false
}

func poolRange(tr protocol.Traits) (uint16, uint16) {
	if tr.PortAlloc == protocol.AllocPool && tr.PortRangeHi > tr.PortRangeLo {
		return tr.PortRangeLo, tr.PortRangeHi
	}
	return 0, 0
}

// ---- per-side build (phase 1) ----

// sprayReq is a predict or random stage pending its grant.
type sprayReq struct {
	kind     protocol.StageKind
	atMs     uint16
	ttl      uint8 // the template's, 0 with low TTL disabled
	want     int
	steps    []int16
	anchor   uint16
	lo, hi   uint16
	rangeCap int // random only: distinct non-filtered ports available in [lo,hi]
}

// sideBuild is the resolved template of one role's family before the shared
// budget is split (phase 1).
type sideBuild struct {
	role        protocol.SideRole
	sendDelayMs uint16
	sockets     int // the template's sockets after the single-socket rule
	maxPPS      uint16
	newPerSec   uint16 // the template's cap on new destinations a second, 0 for none
	openPerSec  uint16 // the template's socket pacing (FamilySide.OpenPerSec)
	sprayIP     netip.Addr
	direct      []protocol.Stage // Direct stages with their targets
	lan         *protocol.Stage  // the LAN stage, nil without a shared LAN
	fresh       *protocol.Stage  // the fresh or fresh_peer stage, nil without one
	directPorts int              // distinct Direct destinations
	sprays      []sprayReq
	sprayTotal  int
	neededWinMs int
	active      bool
}

// buildSideTemplate resolves one role's template for one family (phase 1).
// Every stage keeps the template's ttl, or none when low TTL is disabled;
// spray stages are dropped when the path is blocked or the peer has no
// verified public IP to aim them at. A predicted peer's stages are centred
// on its port extrapolated to the fire time (predictPeer). A first round —
// of the session, or of the ladder an escalation switched to — carries the
// plain-punching baseline (withBaseline), whatever rung it runs.
// With a shared LAN the side also gets the LAN stage.
func buildSideTemplate(in input, fp familyPlan, tmpl sideTmpl, vr variant, isSprayer bool, roleIdx int, blocked, single bool) sideBuild {
	peerFV, _ := findFamily(in.Views[1-roleIdx], fp.Family)
	peerTr := peerFV.Traits
	pa := peerAddrsOf(fp, peerFV)
	if seen := seenTargets(in, fp, roleIdx, pa); len(seen) > 0 {
		pa.direct, pa.guess, pa.sprayIP = seen, nil, seen[0].Addr().Unmap()
	}
	targets, sprayIP := pa.direct, pa.sprayIP
	var pred prediction
	if sprayIP.IsValid() {
		pred = predictPeer(in, 1-roleIdx, peerTr, sprayIP)
	}
	ttlOK := lowTTLEnabled(in.Policy)
	lo, hi := poolRange(peerTr)

	sb := sideBuild{role: tmpl.role, sendDelayMs: tmpl.sendDelayMs, sockets: int(tmpl.sockets), maxPPS: tmpl.maxPPS, sprayIP: sprayIP,
		newPerSec: tmpl.newPerSec, openPerSec: tmpl.openPerSec}
	if single {
		sb.sockets = 1
	}
	var reply []protocol.Stage
	for _, st := range tmpl.stages {
		ttl := stageTTL(st, ttlOK)
		switch st.kind {
		case protocol.StageDirect:
			if len(targets) == 0 {
				continue
			}
			sb.direct = append(sb.direct, protocol.Stage{Kind: protocol.StageDirect, AtMs: st.atMs,
				Targets: append([]netip.AddrPort(nil), targets...), Repeats: st.repeats, TTL: ttl})
		case protocol.StagePredict:
			if blocked || !sprayIP.IsValid() || pred.anchor == 0 {
				continue
			}
			steps := slices.Clone(st.steps) // the template is shared and read-only
			if len(steps) == 0 {
				steps = pred.steps
			}
			want := max(int(st.span), pred.minSpan)
			if pairedFamily(in, fp) {
				want = int(st.span) // the peer's own span, not a spread of timing error (pairSeqWindows)
			}
			sb.sprays = append(sb.sprays, sprayReq{kind: protocol.StagePredict, atMs: st.atMs, ttl: ttl, want: want, steps: steps, anchor: pred.anchor})
			sb.sprayTotal += want
		case protocol.StageRandom:
			if blocked || !sprayIP.IsValid() {
				continue
			}
			sb.sprays = append(sb.sprays, sprayReq{kind: protocol.StageRandom, atMs: st.atMs, ttl: ttl, want: int(st.count), lo: lo, hi: hi,
				rangeCap: RangeCapacity(lo, hi, nil)})
			sb.sprayTotal += int(st.count)
		case protocol.StageFresh:
			sb.fresh = freshStage(st, ttl, familyTraits(in.Views[roleIdx], fp.Family), peerTr, targets, sprayIP, blocked)
		case protocol.StageReplyOnly:
			reply = append(reply, protocol.Stage{Kind: protocol.StageReplyOnly, AtMs: st.atMs})
		}
	}
	if len(sb.direct) > 0 && len(pa.guess) > 0 {
		// The local-port guess, D(2) beside the template's Direct stage
		// with its time and ttl, from every round socket.
		first := sb.direct[0]
		sb.direct = append(sb.direct, protocol.Stage{Kind: protocol.StageDirect, AtMs: first.AtMs, Targets: slices.Clone(pa.guess),
			Repeats: guessRepeats, TTL: first.TTL})
	}
	if (in.Round == 1 || fp.Restart) && len(targets) > 0 && takesBaseline(fp, roleIdx) {
		sb.direct = withBaseline(sb.direct, targets, tmpl.sendDelayMs)
	}
	if rs := resendStage(in, fp, tmpl, roleIdx, sprayIP, ttlOK, blocked); rs != nil {
		sb.direct = append(sb.direct, *rs)
	}
	sb.direct = append(sb.direct, reply...)
	sb.directPorts = len(directDests(sb.direct))
	sb.lan = lanStage(pa.lan, pa.overlay)

	// Medium-confidence fallback: an EIM/Medium peer gets a small ±8 predict
	// neighbourhood in the first round.
	if anchor := peerTr.Observed.Port(); in.Round == 1 && !blocked && openMapping(peerTr) && peerTr.MappingConf == protocol.ConfMedium &&
		sprayIP.IsValid() && anchor != 0 && len(sb.sprays) == 0 {
		sb.sprays = append(sb.sprays, sprayReq{kind: protocol.StagePredict, atMs: 0, want: mediumFallbackSpan, steps: []int16{1}, anchor: anchor})
		sb.sprayTotal += mediumFallbackSpan
	}

	// Window floor: extend so the full birthday set can be emitted at
	// the new-targets rate.
	nps := effNPS(in)
	if vr.extendWindow && isSprayer && sb.sprayTotal > newTargetBurst && nps > 0 {
		sb.neededWinMs = ceilDiv(sb.sprayTotal-newTargetBurst, nps) * 1000
	}
	sb.active = len(sb.sprays) > 0 || sb.directPorts > 0 || sb.lan != nil || sb.fresh != nil
	return sb
}

// stageTTL is the low-TTL hop a template stage puts on the wire: its own,
// whatever its kind, or 0 (the normal TTL) when the policy disables low TTL.
func stageTTL(st stageTmpl, ttlOK bool) uint8 {
	if !ttlOK {
		return 0
	}
	return st.ttl
}

// lanStage is the Direct stage toward the peer's LAN endpoints and overlay
// endpoints: at most four LAN and two overlay
// targets of two packets each, sent from the primary socket at the fire
// time — before or with the public Direct stages — at the normal TTL, since
// no NAT lies between the two. It never shares a stage, and so its repeats,
// with public targets. nil without a target.
func lanStage(lan, overlay []netip.AddrPort) *protocol.Stage {
	targets := append(slices.Clone(lan[:min(len(lan), protocol.MaxLANTargets)]), overlay[:min(len(overlay), protocol.MaxOverlayTargets)]...)
	if len(targets) == 0 {
		return nil
	}
	return &protocol.Stage{Kind: protocol.StageDirect, Targets: targets, Repeats: protocol.LANRepeats}
}

// lanPackets is what the LAN stage sends: each target its repeats, from the
// primary socket only.
func lanPackets(st *protocol.Stage) int {
	if st == nil {
		return 0
	}
	return len(st.Targets) * int(st.Repeats)
}

// fitLAN trims the LAN stage to at most budget packets, dropping the later
// targets first, then the second repeat. The stage is copied.
func fitLAN(st *protocol.Stage, budget int) *protocol.Stage {
	if st == nil || budget <= 0 {
		return nil
	}
	out := *st
	out.Targets = out.Targets[:min(len(out.Targets), max(budget/int(out.Repeats), 1))]
	if lanPackets(&out) > budget {
		out.Repeats = 1
	}
	return &out
}

// mediumFallbackSpan is the ±8 neighbourhood of a Medium EIM peer;
// newTargetBurst the sender's new-target burst.
const (
	mediumFallbackSpan = 16
	newTargetBurst     = 16
)

// ---- round build (phase 2) ----

// buildSides builds both roles' FamilySides and the round window. Each
// family's side is bounded by its own class; per role, the families share
// the round class's sockets and packets (and the remaining session budget)
// and the new-target bucket of the window.
func buildSides(in input, picks []familyPick, roundClass protocol.BudgetClass) ([2][]protocol.FamilySide, time.Duration) {
	roundLim, _ := roundClass.Limits()
	sessB := protocol.TightenBudget(in.Policy.Budget)
	nps := effNPS(in)
	blocked := pathBlocked(in)
	nf := len(picks)

	// Phase 1: resolve every (family, role) template.
	builds := make([][2]sideBuild, nf)
	reqWinMs := 0
	for fi, p := range picks {
		if !p.running() {
			continue
		}
		fp := in.fams[fi]
		reqWinMs = max(reqWinMs, int(p.vr.windowMs))
		sprayerRole := sprayerRoleIndex(p.vr, fp.SideA)
		for role := range 2 {
			isSprayer := sprayerRole == -1 || sprayerRole == role || sprayerRole == 2
			sb := buildSideTemplate(in, fp, roleTemplate(p.vr, fp.SideA, role), p.vr, isSprayer, role, blocked, p.singleSocket[role])
			builds[fi][role] = sb
			reqWinMs = max(reqWinMs, sb.neededWinMs)
		}
	}

	// The window: the largest family's, clamped to [700 ms, Remaining − D]
	// and the round class's longest window, 10 s or 45 s for the slow
	// birthday; the grants below are computed for it.
	win := clampWindow(time.Duration(reqWinMs)*time.Millisecond, in.Remaining-in.D, roundClass)
	winMs := int(win / time.Millisecond)

	var sides [2][]protocol.FamilySide
	for role := range 2 {
		sockCap := int(protocol.MinSet(roundLim.MaxSockets, cmp.Or(sessB.MaxSockets, roundLim.MaxSockets)))
		pktCap := int(roundLim.MaxPackets)
		if in.BudgetLeft[role] >= 0 {
			pktCap = min(pktCap, in.BudgetLeft[role])
		}
		newCap := max(roleNPS(nps, picks, builds, role)*(winMs-sprayStartMs(builds, role))/1000+newTargetBurst, 0)

		sockReq := make([]int, nf)
		sprayReqN := make([]int, nf)
		for fi, p := range picks {
			if !p.running() {
				continue
			}
			lim, _ := p.class.Limits()
			sb := builds[fi][role]
			sockReq[fi] = min(sb.sockets, int(lim.MaxSockets))
			avail := int(lim.MaxDistinctPorts) - in.Recent10sDistinct[role] - sb.directPorts
			sprayReqN[fi] = clampInt(sb.sprayTotal, 0, max(avail, 0))
		}
		sockGrant := allocate(sockReq, sockCap)
		ensureMinSockets(sockGrant, builds, role, sockCap)
		sprayGrant := allocate(sprayReqN, newCap)
		freshGrant := freshSockets(picks, builds, role, sockGrant, sockCap)

		// Each family asks for the packets its stages expand to with the
		// sockets it got; the families share pktCap.
		pktReq := make([]int, nf)
		for fi, p := range picks {
			if !p.running() {
				continue
			}
			lim, _ := p.class.Limits()
			sb := builds[fi][role]
			fresh := FreshPackets(deref(fitFresh(sb.fresh, freshGrant[fi], int(lim.MaxPackets))))
			pktReq[fi] = min(lanPackets(sb.lan)+directPackets(sb.direct, max(sockGrant[fi], 1))+fresh+sprayGrant[fi], int(lim.MaxPackets))
		}
		pktGrant := allocate(pktReq, pktCap)

		for fi, p := range picks {
			fam := in.fams[fi].Family
			if !p.running() {
				sides[role] = append(sides[role], replyOnlySide(fam))
				continue
			}
			lim, _ := p.class.Limits()
			sides[role] = append(sides[role], emitFamilySide(builds[fi][role], fam, lim, sessB, sockGrant[fi], freshGrant[fi], pktGrant[fi], sprayGrant[fi]))
		}
	}
	pairSeqWindows(in, picks, &sides)
	return sides, win
}

// emitFamilySide assembles one role's FamilySide for one family from the
// allocated sockets, fresh sockets, packets and spray grant (phase 2). The
// LAN stage comes first, the cheapest and, on a shared LAN, likeliest path;
// public Direct next: when its packets exceed the grant it loses targets,
// then repeats, then sockets (fitDirect); then the fresh stage, cut to its
// sockets and the packets left (fitFresh); the spray stages get what is
// left, predict before random. MaxPackets is exactly what the stages
// expand to. A side with no active stage degrades to reply_only so the
// plan still encodes.
func emitFamilySide(sb sideBuild, fam protocol.Family, lim protocol.ClassLimits, sessB protocol.Budget, sockGrant, freshGrant, pktGrant, sprayGrant int) protocol.FamilySide {
	sockets := int(clampSockets(uint16(clampInt(sockGrant, 1, 0xFFFF)), lim.MaxSockets, sessB.MaxSockets))
	lan := fitLAN(sb.lan, pktGrant)
	direct, sockets := fitDirect(sb.direct, sockets, pktGrant-lanPackets(lan))
	packets := lanPackets(lan) + directPackets(direct, sockets)
	var stages []protocol.Stage
	distinct := 0
	if lan != nil {
		stages = append(stages, *lan)
		distinct = len(lan.Targets)
	}
	stages = append(stages, direct...)
	distinct = max(distinct, len(directDests(direct)))
	if fresh := fitFresh(sb.fresh, freshGrant, pktGrant-packets); fresh != nil {
		stages = append(stages, *fresh)
		packets += FreshPackets(*fresh)
		distinct += freshPorts(fresh, direct)
	}
	rem := min(sprayGrant, pktGrant-packets)
	for _, sr := range sb.sprays {
		give := min(sr.want, rem)
		if sr.kind == protocol.StageRandom && sr.rangeCap > 0 {
			give = min(give, sr.rangeCap)
		}
		if give <= 0 {
			continue
		}
		switch sr.kind {
		case protocol.StagePredict:
			stages = append(stages, protocol.Stage{Kind: protocol.StagePredict, AtMs: sr.atMs, TTL: sr.ttl, IP: sb.sprayIP, Anchor: sr.anchor, Steps: sr.steps,
				Span: uint16(give)})
		case protocol.StageRandom:
			stages = append(stages, protocol.Stage{Kind: protocol.StageRandom, AtMs: sr.atMs, TTL: sr.ttl, IP: sb.sprayIP, Count: uint16(give), Lo: sr.lo, Hi: sr.hi})
		}
		rem -= give
		packets += give
		distinct += give
	}

	active := false
	for _, st := range stages {
		active = active || st.Kind != protocol.StageReplyOnly
	}
	if !active {
		return replyOnlySide(fam)
	}
	role := sb.role
	if sb.sendDelayMs > 0 {
		role = protocol.SideSender // d > 0 is always a sender
	}
	return protocol.FamilySide{
		Family:           fam,
		Role:             role,
		SendDelayMs:      sb.sendDelayMs,
		Sockets:          uint16(sockets),
		MaxPackets:       uint32(packets),
		MaxPPS:           protocol.MinSet(sb.maxPPS, protocol.MinSet(lim.MaxPPS, cmp.Or(sessB.MaxPPS, lim.MaxPPS))),
		MaxNewPerSec:     protocol.MinSet(sb.newPerSec, uint16(effNPS0(sessB))),
		MaxDistinctPorts: uint16(min(distinct, int(lim.MaxDistinctPorts))),
		OpenPerSec:       sb.openPerSec,
		Stages:           stages,
	}
}

// replyOnlySide is a family side that initiates nothing: a reply_only stage
// keeps the plan encodable.
func replyOnlySide(fam protocol.Family) protocol.FamilySide {
	return protocol.FamilySide{Family: fam, Role: protocol.SideReplyOnly, Sockets: 1,
		Stages: []protocol.Stage{{Kind: protocol.StageReplyOnly}}}
}

// directDests is the distinct destinations of the Direct stages: the
// baseline, the template's and the resend stage may aim at the same
// targets or at different ones.
func directDests(stages []protocol.Stage) []netip.AddrPort {
	var dests []netip.AddrPort
	for _, st := range stages {
		if st.Kind != protocol.StageDirect {
			continue
		}
		for _, t := range st.Targets {
			if !slices.Contains(dests, t) {
				dests = append(dests, t)
			}
		}
	}
	return dests
}

// directPackets is what the Direct stages send: every round socket sends
// each target its repeats.
func directPackets(stages []protocol.Stage, sockets int) int {
	n := 0
	for _, st := range stages {
		if st.Kind == protocol.StageDirect {
			n += sockets * len(st.Targets) * int(st.Repeats)
		}
	}
	return n
}

// fitDirect trims the Direct stages to at most budget packets: first the
// later targets (the peer's first mapping stays), then repeats, then
// sockets, and finally whole stages. The stages are copied; reply_only
// stages are kept.
func fitDirect(stages []protocol.Stage, sockets, budget int) ([]protocol.Stage, int) {
	budget = max(budget, 0)
	out := make([]protocol.Stage, len(stages))
	copy(out, stages)
	most := func(f func(protocol.Stage) int) int {
		best, at := 1, -1
		for i, st := range out {
			if st.Kind == protocol.StageDirect && f(st) > best {
				best, at = f(st), i
			}
		}
		return at
	}
	for directPackets(out, sockets) > budget {
		if i := most(func(st protocol.Stage) int { return len(st.Targets) }); i >= 0 {
			out[i].Targets = out[i].Targets[:len(out[i].Targets)-1]
			continue
		}
		if i := most(func(st protocol.Stage) int { return int(st.Repeats) }); i >= 0 {
			out[i].Repeats--
			continue
		}
		if per := directPackets(out, 1); sockets > 1 && per > 0 && per <= budget {
			sockets = budget / per
			continue
		}
		// One target, one repeat, one socket per stage and still too many:
		// drop the last Direct stage.
		for i := len(out) - 1; i >= 0; i-- {
			if out[i].Kind == protocol.StageDirect {
				out = append(out[:i], out[i+1:]...)
				break
			}
		}
		sockets = 1
	}
	return out, sockets
}

// ---- small helpers ----

// sprayerRoleIndex maps the variant's canonical birthday side to a role index
// (0 initiator, 1 responder, 2 both), or -1 when the round is not a tiered
// birthday round (then every spraying side may extend its window).
func sprayerRoleIndex(vr variant, sideA protocol.Role) int {
	switch vr.sprayer {
	case bsBoth:
		return 2
	case bsA:
		return roleIndex(sideA)
	case bsB:
		return roleIndex(sideA.Peer())
	default:
		return -1
	}
}

func sprayStartMs(builds [][2]sideBuild, role int) int {
	start := -1
	for fi := range builds {
		for _, sr := range builds[fi][role].sprays {
			if start < 0 || int(sr.atMs) < start {
				start = int(sr.atMs)
			}
		}
	}
	return max(start, 0)
}

// freshSockets splits the role's sockets left after the round sockets over
// the families' fresh stages: each within its own class's socket
// ceiling, the earlier family first. A family without one gets 0.
func freshSockets(picks []familyPick, builds [][2]sideBuild, role int, sockGrant []int, sockCap int) []int {
	used := 0
	for _, g := range sockGrant {
		used += max(g, 1)
	}
	out := make([]int, len(picks))
	for fi, p := range picks {
		fresh := builds[fi][role].fresh
		if !p.running() || fresh == nil || fresh.Kind != protocol.StageFresh {
			continue
		}
		lim, _ := p.class.Limits()
		out[fi] = clampInt(int(fresh.Count), 0, max(min(sockCap-used, int(lim.MaxSockets)-max(sockGrant[fi], 1)), 0))
		used += out[fi]
	}
	return out
}

// deref is *st, or the zero stage for nil.
func deref(st *protocol.Stage) protocol.Stage {
	if st == nil {
		return protocol.Stage{}
	}
	return *st
}

// ensureMinSockets gives each active family at least one socket, as long as the
// shared cap allows (it always does: cap >= 2 and at most two families).
func ensureMinSockets(grant []int, builds [][2]sideBuild, role, cap int) {
	used := 0
	for _, g := range grant {
		used += g
	}
	for fi := range grant {
		if grant[fi] == 0 && builds[fi][role].active && used < cap {
			grant[fi] = 1
			used++
		}
	}
}

// allocate splits a shared cap over per-family requests, giving each an even
// share first (remainder to the earlier families) and then handing any leftover
// to families that still want more, so the sum never exceeds cap.
func allocate(reqs []int, cap int) []int {
	n := len(reqs)
	out := make([]int, n)
	if n == 0 || cap <= 0 {
		return out
	}
	share, rem := cap/n, cap%n
	used := 0
	for i := range reqs {
		base := share
		if i < rem {
			base++
		}
		out[i] = min(reqs[i], base)
		used += out[i]
	}
	for i := range reqs {
		if used >= cap {
			break
		}
		if add := min(reqs[i]-out[i], cap-used); add > 0 {
			out[i] += add
			used += add
		}
	}
	return out
}

// clampWindow clamps a round window to [700 ms, min(hi, the class's longest
// window)], where hi is Remaining − D: the round fires D after now and must
// end by punchDeadline. The longest window is 10 s, 45 s for the
// slow birthday's background class.
func clampWindow(win, hi time.Duration, class protocol.BudgetClass) time.Duration {
	return max(min(win, hi, time.Duration(class.MaxWindowMs())*time.Millisecond), minWindow)
}

// roleNPS is the new-destination rate a role's sprays share: the session's
// rate, or a running family's lower template cap (the slow birthday's 25 a
// second).
func roleNPS(nps int, picks []familyPick, builds [][2]sideBuild, role int) int {
	for fi, p := range picks {
		if n := int(builds[fi][role].newPerSec); p.running() && n > 0 && n < nps {
			nps = n
		}
	}
	return nps
}

// effNPS is the new-targets-per-second rate: the ladder value capped by the
// session budget.
func effNPS(in input) int {
	return effNPS0(protocol.TightenBudget(in.Policy.Budget))
}

func effNPS0(sessB protocol.Budget) int {
	n := ladderNPS
	if sessB.MaxNewPerSec > 0 && int(sessB.MaxNewPerSec) < n {
		n = int(sessB.MaxNewPerSec)
	}
	return n
}

func clampSockets(want, classMax, sessMax uint16) uint16 {
	v := max(want, 1)
	if classMax > 0 {
		v = min(v, classMax)
	}
	if sessMax > 0 {
		v = min(v, sessMax)
	}
	return max(v, 1)
}

func ceilDiv(a, b int) int {
	if b <= 0 {
		return 0
	}
	return (a + b - 1) / b
}

func clampInt(v, lo, hi int) int {
	return min(max(v, lo), hi)
}
