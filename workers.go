package holepunch

import (
	"net/netip"
	"slices"
	"sync/atomic"

	"github.com/djylb/holepunch/internal/candidate"
	"github.com/djylb/holepunch/internal/netaddr"
	"github.com/djylb/holepunch/internal/plan"
	"github.com/djylb/holepunch/protocol"
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
// the peer runs on this host (sameHost); a target of any other kind than
// Direct passes admitIP; a low or sensitive port only when it is exactly a
// known peer endpoint.
func (w *worker) admit(rt *runtime, ap netip.AddrPort, kind protocol.StageKind) (ok bool, perTarget int) {
	ap = netaddr.Canon(ap)
	if kind != protocol.StageDirect {
		return ap.Port() != 0 && w.admitIP(rt, ap.Addr()), 0
	}
	a := ap.Addr()
	if !w.fam.UsableTarget(ap) || rt.isLocal(a) && !w.sameHost(rt, ap) {
		return false, 0
	}
	if (ap.Port() < 1024 || plan.SensitivePort(ap.Port())) && !w.endpoints[ap] && !w.isRemapped(ap) {
		return false, 0
	}
	switch {
	case w.verifiedIP(a):
		return true, 0
	case w.lan[a] || w.overlay[a]:
		return true, protocol.LANRepeats
	case w.unverified && w.reported[a]:
		return true, protocol.UnverifiedRepeats
	}
	return false, 0
}

// admitIP is the admission of an IP the side sprays ports of — a predict,
// random, fresh or fresh_peer stage's, or a pushed port window's: a verified
// IP of the peer that is not private and not one of this host's.
func (w *worker) admitIP(rt *runtime, a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	return w.fam.Matches(a) && !netaddr.Unusable(a) && !rt.isLocal(a) && w.verifiedIP(a) && !netaddr.Private(a)
}

// stageAdmission is what admission leaves of one stage of a side.
type stageAdmission struct {
	ip       netip.Addr       // the admitted IP of a predict, random, fresh_peer or fresh stage; invalid when it has none
	targets  []admittedTarget // the admitted targets of a Direct or fresh stage
	rejected int              // targets and IPs refused
}

// admittedTarget is an admitted Direct target: its canonical address, its
// index in the stage and its per-round packet cap (0: none).
type admittedTarget struct {
	to    netip.AddrPort
	index int
	per   int
}

// admitStage applies admission to stage st of side: the one rule behind
// punch_ready.rejected and round_result.rejected. A reply-only side initiates
// nothing, so nothing of it is admitted or refused. A Direct stage keeps the
// targets admit passes; a predict, random or fresh_peer stage needs its IP
// to pass admitIP; a fresh stage keeps the targets admit passes and needs
// its IP, when set, to pass admitIP, or it sends nothing. Under the
// NoPrediction ablation and in a family the server could not verify, the
// stages that predict where the peer's mappings will be — predict, random,
// fresh and fresh_peer — are refused whole, each counting once.
func (w *worker) admitStage(rt *runtime, side protocol.FamilySide, st protocol.Stage) stageAdmission {
	var adm stageAdmission
	if side.Role == protocol.SideReplyOnly {
		return adm
	}
	direct := func() {
		for i, t := range st.Targets {
			if ok, per := w.admit(rt, t, protocol.StageDirect); ok {
				adm.targets = append(adm.targets, admittedTarget{to: netaddr.Canon(t), index: i, per: per})
			} else {
				adm.rejected++
			}
		}
	}
	switch st.Kind {
	case protocol.StageDirect:
		direct()
	case protocol.StagePredict, protocol.StageRandom, protocol.StageFreshPeer, protocol.StageFresh:
		if rt.abl.NoPrediction || w.unverified {
			adm.rejected = 1
			return adm
		}
		if st.Kind == protocol.StageFresh {
			direct()
			if !st.IP.IsValid() {
				return adm
			}
		}
		if w.admitIP(rt, st.IP) {
			adm.ip = st.IP.Unmap().WithZone("")
		} else {
			adm.targets = nil
			adm.rejected++
		}
	case protocol.StageReplyOnly:
	}
	return adm
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
// At most protocol.MaxDrifted are kept.
func (w *worker) adoptRemap(ap netip.AddrPort) {
	a := ap.Addr()
	if !w.verified[a] && !netaddr.Public(a) {
		return
	}
	for {
		cur := w.remapped.Load()
		var list []netip.AddrPort
		if cur != nil {
			list = *cur
		}
		if len(list) >= protocol.MaxDrifted || slices.Contains(list, ap) {
			return
		}
		next := append(slices.Clip(list), ap)
		if w.remapped.CompareAndSwap(cur, &next) {
			return
		}
	}
}

// sameHost reports whether a Direct target on one of this host's addresses
// is the peer itself, running on this host: a LAN address of the peer at a
// port no socket of this session holds. The port rule and the role check
// keep the session from punching itself.
func (w *worker) sameHost(rt *runtime, ap netip.AddrPort) bool {
	return w.lan[ap.Addr()] && !rt.socks.ownsPort(w.fam, ap.Port())
}

// addrKind is the candidate kind k of a pair toward the peer's address a,
// as the summary's addresses refine it: overlay toward one of the peer's
// overlay addresses, lan toward one of its LAN addresses unless k says
// overlay.
func (w *worker) addrKind(a netip.Addr, k candidate.Kind) candidate.Kind {
	switch {
	case w.overlay[a]:
		return candidate.KindOverlay
	case w.lan[a] && k != candidate.KindOverlay:
		return candidate.KindLAN
	}
	return k
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
			if overlay && len(w.overlay) < protocol.MaxOverlayTargets {
				w.overlay[a] = true
			}
		case e.Verified:
			w.verified[a] = true
			w.allow[ap.Port()] = struct{}{}
		case e.Source == protocol.EndpointLAN && sameLAN && len(w.lan) < protocol.MaxLANTargets && netaddr.Private(a):
			w.lan[a] = true
		case w.unverified && netaddr.Public(a) && len(w.reported) < protocol.MaxReportedIPs:
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
	return w.samePublic && w.fam.UsableTarget(ap) && netaddr.Private(a) &&
		ap.Port() >= 1024 && !plan.SensitivePort(ap.Port()) && !rt.isLocal(a)
}
