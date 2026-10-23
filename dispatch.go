package holepunch

import (
	"net/netip"
	"sync"
	"time"

	"github.com/djylb/holepunch/internal/candidate"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/internal/probe"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/protocol"
)

// The receive path: every datagram a socket's read loop reads, every ICMP
// report and the relayed peer_seen evidence.

// Per-round reporting limits.
const (
	peerSeenPerRound = 8
	maxRTTSample     = 5 * time.Second
)

// seqWindow is a replay window shared by every socket of the session, one per
// sender role; udpwire.SeqWindow itself is not safe for concurrent use.
type seqWindow struct {
	mu sync.Mutex
	w  udpwire.SeqWindow
}

func (s *seqWindow) accept(seq uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Accept(seq)
}

// dispatch handles one datagram of socket s: a
// datagram in the STUN range is an opener, whose packet goes on, or
// a STUN server's answer for the prober; then length and first byte, the
// pre-AEAD rate limit, AEAD, role, replay, and the per-type handling. Failed
// packets are counted and never answered.
func (rt *runtime) dispatch(s *udpSock, pkt []byte, from netip.AddrPort) {
	fs := rt.fam(s.fam)
	fs.cnt.rx.Add(1)
	at := rt.clk.Now()
	pr := fs.prober.Load()
	if udpwire.Wrapped(pkt) {
		inner, d := udpwire.Unwrap(pkt)
		switch {
		case d == udpwire.OK:
			pkt = inner
		case probe.IsSTUN(pkt):
			if pr != nil {
				pr.DeliverSTUN(s.id, from, pkt, at)
			}
			return
		default:
			rt.undecoded(s, from, at, udpwire.Precheck(pkt, udpwire.MinPeerPacket))
			return
		}
	}
	if d := udpwire.Precheck(pkt, udpwire.MinPeerPacket); d != udpwire.OK {
		rt.undecoded(s, from, at, d)
		return
	}
	if !s.preRateAllow(at) {
		fs.cnt.drop(dropRate)
		return
	}
	var h udpwire.Header
	var t udpwire.TLVs
	if d := rt.codec.Open(pkt, nil, &h, &t); d != udpwire.OK {
		rt.undecoded(s, from, at, d)
		return
	}
	if d := rt.codec.CheckRole(&h); d != udpwire.OK {
		if k, ok := dropOf(d); ok {
			fs.cnt.drop(k)
		}
		return
	}
	switch h.Type {
	case udpwire.TProbeAck, udpwire.TProbeExtra, udpwire.TProbeAlt:
		if !rt.serverWin.accept(h.Seq) {
			fs.cnt.drop(dropReplay)
			return
		}
		if rt.reobserved(s, from, &h, &t) {
			return
		}
		if pr != nil {
			pr.Deliver(s.id, from, &h, &t, at)
		}
	case udpwire.THairpin:
		if pr != nil {
			pr.Deliver(s.id, from, &h, &t, at)
		}
	default:
		if !rt.peerWin.accept(h.Seq) {
			fs.cnt.drop(dropReplay)
			return
		}
		rt.onPeerPacket(s, from, &h, &t, at)
	}
}

// undecoded counts a packet that is not this session's and checks whether
// it is the handover's upper-layer evidence: a non-holepunch datagram — too
// short, or with a first byte outside [0x04, 0x0F] — or one this session's
// AEAD cannot open, from the nominated remote on its socket (a short
// datagram such as a KCP ack is no holepunch packet either).
// Before Confirm, AEAD failures from a verified peer IP are token_mismatch
// evidence.
func (rt *runtime) undecoded(s *udpSock, from netip.AddrPort, at time.Time, d udpwire.DecodeError) {
	fs := rt.fam(s.fam)
	if k, ok := dropOf(d); ok {
		fs.cnt.drop(k)
	}
	if d != udpwire.ErrForeign && d != udpwire.ErrAuth && d != udpwire.ErrShort {
		return
	}
	st := rt.punch
	if !st.isActive() {
		return
	}
	if rt.nom.watched(s.local, from) {
		rt.nom.post(candEvent{kind: evUpper, local: s.local, remote: from, fam: s.fam, at: at})
		return
	}
	if d == udpwire.ErrAuth && !st.isConfirmed() {
		if w := fs.worker; w != nil && w.verifiedIP(from.Addr()) {
			fs.cnt.tokenMismatch.Add(1)
		}
	}
}

// readFailed tells the nomination state machine that socket s can no longer
// read: its pairs are never nominated again and, on the winning socket,
// silence is no longer handover evidence.
func (rt *runtime) readFailed(s *udpSock) {
	if rt.punch.isActive() {
		rt.nom.post(candEvent{kind: evReadFailed, local: s.local, fam: s.fam, at: rt.clk.Now()})
	}
}

// onPeerPacket handles an authentic, fresh packet of the peer.
func (rt *runtime) onPeerPacket(s *udpSock, from netip.AddrPort, h *udpwire.Header, t *udpwire.TLVs, at time.Time) {
	st := rt.punch
	if !st.isActive() {
		return
	}
	fs := rt.fam(s.fam)
	fs.cnt.verified.Add(1)
	pa := st.notePeer(s.fam, s.local, from, h.Type == udpwire.TSuccess)
	if pa.first {
		rt.phases.advanceFamily(s.fam, protocol.PhaseNegotiating, stageFirstPeerPacket, at)
		rt.progress(progressEvent{stage: stageFirstPeerPacket, status: protocol.StatusOK, family: s.fam, round: pa.round, remote: from})
	}
	if pa.reportSeen && !rt.abl.NoAssistRelay {
		// P2: a full queue drops the newest, which controlwire reports as
		// ErrQueueFull; peer_seen is best effort.
		_ = rt.ctl.send(protocol.Assist{
			SessionID: rt.start.SessionID, Role: rt.role, Kind: protocol.AssistPeerSeen, Round: pa.round, Family: s.fam,
			Remote: from, Local: s.local, Sock: h.Sock, Cand: h.Cand, Type: uint8(h.Type), First: pa.first,
		})
	}
	if pa.newPair && !rt.sender.everSent(from.Addr()) {
		if res := fs.table(); res != nil {
			res.NoteUnsolicitedInbound(s.id, from.Addr())
		}
	}
	ev := candEvent{local: s.local, remote: from, fam: s.fam, at: at, epoch: h.Aux, peerSock: h.Sock, slot: t.Slot, paths: t.Paths}
	switch {
	case pa.known:
		ev.ckind = pa.kind
	case fs.worker != nil && fs.worker.overlay[from.Addr()]:
		// A peer-reflexive source on the peer's overlay: the path runs
		// through the tunnel and ranks as one.
		ev.ckind = candidate.KindOverlay
	}
	switch h.Type {
	case udpwire.TPunch:
		rt.replySuccess(s, from, h)
		ev.kind = evPacket
	case udpwire.TSuccess:
		ev.kind = evPacket
		ev.rtt = rt.rttSample(h.EchoTS)
	case udpwire.TNominate:
		ev.kind = evNominate
	case udpwire.TAccept:
		ev.kind = evAccept
	case udpwire.TReady:
		ev.kind = evReady
	case udpwire.THandoverAck:
		ev.kind = evAck
	default:
		return
	}
	rt.nom.post(ev)
}

// rttSample is the UDP RTT of a success echoing our timestamp echoTS (codec
// milliseconds); 0 when unusable.
func (rt *runtime) rttSample(echoTS uint32) time.Duration {
	if echoTS == 0 {
		return 0
	}
	d := time.Duration(rt.codec.Now()-echoTS) * time.Millisecond
	if d > maxRTTSample {
		return 0
	}
	// The same millisecond: an RTT below the timestamps' resolution (a LAN
	// pair), the smallest sample there is, not a missing one.
	return max(d, time.Millisecond)
}

// replySuccess answers a punch from the socket it arrived on (Reply class):
// it echoes the punch's seq, timestamp and cand and tells the peer the
// source we saw (OBSERVED).
func (rt *runtime) replySuccess(s *udpSock, to netip.AddrPort, req *udpwire.Header) {
	fs := rt.fam(s.fam)
	if w := fs.worker; w != nil && !w.verified[to.Addr()] {
		fs.cnt.replyUnlisted.Add(1)
	}
	h := udpwire.Header{Type: udpwire.TSuccess, Round: req.Round, Cand: req.Cand, EchoSeq: req.Seq, EchoTS: req.TS}
	t := udpwire.TLVs{Observed: to, RxCount: uint32(rt.punch.received()), HasRx: true}
	_ = rt.sender.Send(rt.g.Context(), s, to, &h, &t, sendOpt{class: classReply, stage: txReply})
}

// noteICMP counts an ICMP soft signal on socket s and lets the
// prober see it while probing.
func (rt *runtime) noteICMP(s *udpSock) {
	fs := rt.fam(s.fam)
	if pr := fs.prober.Load(); pr != nil {
		pr.NoteUnreachable(s.id)
	}
	if rt.punch.isActive() {
		rt.punch.noteICMP(s.fam)
	}
}

// onPeerSeen consumes a relayed peer_seen: the peer received our packet
// from socket a.Sock aimed at our target a.Cand, and saw it come from
// a.Remote. The remote is evidence only — never a target. It feeds
// the observation table (drift, traits correction) and, when the peer still
// has not been heard 200 ms later, a follow-up of three punches on the
// exact (socket, target) pair that got through.
func (rt *runtime) onPeerSeen(a protocol.Assist, at time.Time) {
	w := rt.fam(a.Family).worker
	if w == nil {
		return
	}
	rt.fam(a.Family).cnt.peerSeenUs.Store(true)
	target, known := rt.punch.notePeerSeen(a.Family, a.Sock, a.Cand)
	if !known {
		return
	}
	if tab := w.fs.table(); tab != nil && a.Remote.IsValid() {
		k := nat.PointKey{Socket: a.Sock, Source: nat.SourcePeer, Peer: target}
		if tab.Record(k, a.Remote, at.Sub(rt.startAt), 0, 0) {
			rt.punch.noteDrift(a.Family)
			rt.progress(progressEvent{stage: stageDriftDetected, status: protocol.StatusInfo, family: a.Family})
		}
		rt.traitsSource[a.Family.Index()].Store(true)
	}
	rt.followUp(a.Family, a.Sock, target)
}
