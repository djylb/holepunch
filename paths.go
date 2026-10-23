package holepunch

import (
	"net/netip"
	"time"

	"github.com/djylb/holepunch/internal/candidate"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/protocol"
)

// pathKind is the kind of network the pair toward remote of family fam runs
// over (PathInfo.Kind): portmap toward a port mapping of the peer,
// overlay toward its overlay address, lan toward its LAN address, public
// otherwise. k is the pair's candidate kind.
func (rt *runtime) pathKind(fam protocol.Family, remote netip.AddrPort, k candidate.Kind) protocol.PathKind {
	w := rt.fam(fam).worker
	if rt.punch.isPortmap(remote) || w != nil && w.portmap[remote] {
		return protocol.PathPortmap
	}
	if w != nil {
		k = w.addrKind(remote.Addr(), k)
	}
	return k.PathKind()
}

// pathInfo describes the confirmed pair c, of the campaign at epoch, for
// round_result, punch_result and Diagnostics.
func (rt *runtime) pathInfo(c candidate.Candidate, epoch uint16) protocol.PathInfo {
	p := protocol.PathInfo{
		Family: c.Family, Local: c.Local, Remote: c.Remote, Round: rt.currentRound(), Epoch: epoch,
		Cand: udpwire.NoCand, CandKind: c.CandKind(), Kind: rt.pathKind(c.Family, c.Remote, c.Kind),
		RTTMs: rttMs(c.MinRTT),
	}
	if s := rt.socks.byAddr(c.Local); s != nil {
		p.Sock = s.id
	}
	if cand, ok := rt.punch.candFor(p.Sock, c.Remote); ok {
		p.Cand = cand
	}
	return p
}

// rttMs is an RTT in the wire's whole milliseconds.
func rttMs(d time.Duration) uint16 { return uint16(min(d/time.Millisecond, 0xFFFF)) }

// confirmedPaths describes the paths handed over with win for punch_result,
// Diagnostics and Result, all from the pairs as the handover decision left
// them: the primary path as Confirm described it — what round_result
// reported — with the minimum RTT measured up to the handover, and the extra
// paths, confirmed by the same evidence.
func (rt *runtime) confirmedPaths(win *candidate.Action, ho *handoff) (primary protocol.PathInfo, extra []protocol.PathInfo) {
	primary = rt.punch.path()
	if rtt := ho.primary.c.MinRTT; rtt > 0 {
		primary.RTTMs = rttMs(rtt)
	}
	primary.ConfirmedBy = win.ConfirmedBy
	for _, hp := range ho.paths() {
		p := rt.pathInfo(hp.c, win.Epoch)
		p.ConfirmedBy = win.ConfirmedBy
		extra = append(extra, p)
	}
	return primary, extra
}

// result builds Result for the primary path; session adds the extra paths.
func (rt *runtime) result(primary handPath) Result {
	r := Result{
		SessionID: rt.start.SessionID, Role: rt.role,
		Path:          rt.path(rt.primaryPath, primary),
		TransportMode: rt.transport.Mode, PeerTransportData: rt.transport.PeerData,
		TransportTimeout: time.Duration(rt.timeouts.TransportTimeoutMs) * time.Millisecond,
		Rounds:           len(rt.roundsRun), Timing: rt.publicTiming(),
	}
	for _, rp := range rt.roundsRun {
		if rp.Round == rt.primaryPath.Round {
			r.Variant = rp.Variant
		}
	}
	return r
}

// path is the Path of the handed path hp that info describes, with the
// keepalive its kind of network, the traits of its family and its socket's
// port mapping call for, and the pair's measured minimum RTT.
func (rt *runtime) path(info protocol.PathInfo, hp handPath) Path {
	var self, peer protocol.Traits
	if w := rt.fam(info.Family).worker; w != nil {
		self, peer = w.selfTraits, w.peerTraits
	}
	hs := hp.s
	return Path{Conn: hs.sock.conn, Family: info.Family, Kind: info.Kind, LocalAddr: hs.sock.local, RemoteAddr: info.Remote,
		RTT: hp.c.MinRTT, Keepalive: keepaliveFor(info.Family, info.Kind, self, peer, hs.info), PortMapping: hs.info}
}

// confirmedRemote is the confirmed remote of family f: the primary path's
// when it is of f, else the first extra path's of f.
func confirmedRemote(win *candidate.Action, extra []protocol.PathInfo, f protocol.Family) netip.AddrPort {
	if win.Family == f {
		return win.Remote
	}
	for _, p := range extra {
		if p.Family == f {
			return p.Remote
		}
	}
	return netip.AddrPort{}
}
