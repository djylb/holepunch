package holepunch

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/internal/candidate"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/internal/probe"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/udpwire"
)

// Per-round reporting limits.
const (
	maxSeenFrom      = 4
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

// roundStats is one family's evidence in the current round, the material of
// round_result.families[].
type roundStats struct {
	hit        bool
	seenFrom   []netip.AddrPort
	peerSeenUs bool
	recv       int
	icmp       int
	drift      bool
	peerSeen   int             // peer_seen reports sent this round
	reobserve  reobservation   // the round's re-observation probe in flight
	remap      *protocol.Remap // the new primary mapping it showed, echoed in round_result
}

type sockCand struct {
	sock uint8
	cand uint16
}

type pairKey struct{ local, remote netip.AddrPort }

// punchState is the session's punching evidence, shared by the read loops,
// the nomination goroutine, the round goroutines and the orchestrator. It is
// created with the runtime and lives as long as it; until the summary opens
// it (active) the read loops leave it alone. mu guards the maps and stats; no
// user code and no clock call runs under it.
type punchState struct {
	active    atomic.Bool // set once the workers exist and the nomination goroutine runs (summary accepted)
	converged atomic.Bool // a valid peer packet arrived: spraying stops
	confirmed atomic.Bool
	firstPeer atomic.Bool
	rx        atomic.Int64 // valid peer packets, session total

	mu        sync.Mutex
	round     uint8 // 1 until the first go: what arrives before it belongs to round 1
	stats     map[protocol.Family]*roundStats
	hit       map[netip.AddrPort]bool // remotes a valid packet came from
	seenPairs map[pairKey]bool
	kinds     map[netip.AddrPort]candidate.Kind
	portmaps  map[netip.AddrPort]bool // targets of peer_targets{source: portmap}: their paths are portmap paths
	cands     map[sockCand]netip.AddrPort
	seenSrc   map[netip.AddrPort]bool              // every peer source of the session (attribution)
	remapped  map[protocol.Family][]netip.AddrPort // primary mappings re-observed and reported, at most one a round
	anyHit    bool
	peerSeen  bool
	icmpMax   int

	confirmAt   time.Time
	confirmPath protocol.PathInfo
	handedOver  *candidate.Action
	extras      []candidate.Candidate // the extra paths committed with handedOver
	failed      bool

	wake chan struct{}
}

func newPunchState() *punchState {
	return &punchState{
		stats: map[protocol.Family]*roundStats{}, hit: map[netip.AddrPort]bool{},
		seenPairs: map[pairKey]bool{}, kinds: map[netip.AddrPort]candidate.Kind{}, portmaps: map[netip.AddrPort]bool{},
		cands: map[sockCand]netip.AddrPort{}, seenSrc: map[netip.AddrPort]bool{},
		remapped: map[protocol.Family][]netip.AddrPort{}, wake: make(chan struct{}, 1), round: 1,
	}
}

// notify wakes the orchestrator.
func (st *punchState) notify() {
	select {
	case st.wake <- struct{}{}:
	default:
	}
}

// newRound starts the round's evidence; the previous round's is returned.
func (st *punchState) newRound(round uint8, fams []protocol.Family) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.round = round
	st.stats = map[protocol.Family]*roundStats{}
	for _, f := range fams {
		st.stats[f] = &roundStats{}
	}
}

func (st *punchState) statsFor(f protocol.Family) *roundStats {
	s := st.stats[f]
	if s == nil {
		s = &roundStats{}
		st.stats[f] = s
	}
	return s
}

// planTarget records a planned target's kind and cand for later lookups.
func (st *punchState) planTarget(sock uint8, cand uint16, to netip.AddrPort, k candidate.Kind) {
	st.mu.Lock()
	if old, ok := st.kinds[to]; !ok || k > old {
		st.kinds[to] = k
	}
	st.cands[sockCand{sock, cand}] = to
	st.mu.Unlock()
}

// notePortmap records a target the server sent as one of the peer's port
// mappings (peer_targets{source: portmap}).
func (st *punchState) notePortmap(to netip.AddrPort) {
	st.mu.Lock()
	st.portmaps[to] = true
	st.mu.Unlock()
}

// pathKind is the kind of network the pair toward remote of family fam runs
// over (PathInfo.Kind): portmap toward a port mapping of the peer,
// overlay toward its overlay address, lan toward its LAN address, public
// otherwise. k is the pair's candidate kind.
func (rt *runtime) pathKind(fam protocol.Family, remote netip.AddrPort, k candidate.Kind) protocol.PathKind {
	st := rt.punch
	st.mu.Lock()
	portmap := st.portmaps[remote]
	st.mu.Unlock()
	w := rt.fam(fam).worker
	switch {
	case portmap || w != nil && w.portmap[remote]:
		return protocol.PathPortmap
	case k == candidate.KindOverlay || w != nil && w.overlay[remote.Addr()]:
		return protocol.PathOverlay
	case k == candidate.KindLAN || w != nil && w.lan[remote.Addr()]:
		return protocol.PathLAN
	}
	return protocol.PathPublic
}

// heardOn reports whether a valid peer packet arrived on the socket bound
// at local: its pairs are candidates.
func (st *punchState) heardOn(local netip.AddrPort) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	for pk := range st.seenPairs {
		if pk.local == local {
			return true
		}
	}
	return false
}

// isHit reports whether a valid packet came from to.
func (st *punchState) isHit(to netip.AddrPort) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.hit[to]
}

// startPunching opens the punching state once the workers exist: it starts
// the nomination goroutine with the handover timeout the summary settled
// and then lets the read loops in (active). Neither
// object is replaced: the read loops have been reading both pointers since
// the probing sockets opened, so the summary only hands the nomination
// goroutine its parameters as it starts.
func (rt *runtime) startPunching() {
	cfg := candidate.Config{Role: rt.role, HandoverTimeout: time.Duration(rt.timeouts.HandoverTimeoutMs) * time.Millisecond,
		MaxPaths: rt.opts.MaxPaths}
	rt.pg.Go("nominate", func(ctx context.Context) { rt.nom.run(ctx, cfg) })
	rt.punch.active.Store(true)
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
	if !st.active.Load() {
		return
	}
	if rt.nom.watched(s.local, from) {
		rt.nom.post(candEvent{kind: evUpper, local: s.local, remote: from, fam: s.fam, at: at})
		return
	}
	if d == udpwire.ErrAuth && !st.confirmed.Load() {
		if w := fs.worker; w != nil && w.verifiedIP(from.Addr()) {
			fs.cnt.tokenMismatch.Add(1)
		}
	}
}

// readFailed tells the nomination state machine that socket s can no longer
// read: its pairs are never nominated again and, on the winning socket,
// silence is no longer handover evidence.
func (rt *runtime) readFailed(s *udpSock) {
	if rt.punch.active.Load() {
		rt.nom.post(candEvent{kind: evReadFailed, local: s.local, fam: s.fam, at: rt.clk.Now()})
	}
}

// onPeerPacket handles an authentic, fresh packet of the peer.
func (rt *runtime) onPeerPacket(s *udpSock, from netip.AddrPort, h *udpwire.Header, t *udpwire.TLVs, at time.Time) {
	st := rt.punch
	if !st.active.Load() {
		return
	}
	fs := rt.fam(s.fam)
	fs.cnt.verified.Add(1)
	st.rx.Add(1)
	first := !st.firstPeer.Swap(true)
	st.converged.Store(true)

	st.mu.Lock()
	rs := st.statsFor(s.fam)
	rs.recv++
	if h.Type == udpwire.TSuccess {
		rs.hit = true
		st.anyHit = true
	}
	if len(rs.seenFrom) < maxSeenFrom && !containsAddr(rs.seenFrom, from) {
		rs.seenFrom = append(rs.seenFrom, from)
	}
	st.seenSrc[from] = true
	st.hit[from] = true
	pk := pairKey{s.local, from}
	newPair := !st.seenPairs[pk]
	st.seenPairs[pk] = true
	reportSeen := newPair && rs.peerSeen < peerSeenPerRound
	if reportSeen {
		rs.peerSeen++
	}
	kind, known := st.kinds[from]
	round := st.round
	st.mu.Unlock()

	if first {
		rt.phases.advanceFamily(s.fam, protocol.PhaseNegotiating, stageFirstPeerPacket, at)
		rt.progress(progressEvent{stage: stageFirstPeerPacket, status: protocol.StatusOK, family: s.fam, round: round, remote: from})
	}
	if reportSeen && !rt.abl.NoAssistRelay {
		rt.sendAssist(protocol.Assist{
			SessionID: rt.start.SessionID, Role: rt.role, Kind: protocol.AssistPeerSeen, Round: round, Family: s.fam,
			Remote: from, Local: s.local, Sock: h.Sock, Cand: h.Cand, Type: uint8(h.Type), First: first,
		})
	}
	if newPair && !rt.sender.everSent(from.Addr()) {
		if res := fs.table(); res != nil {
			res.NoteUnsolicitedInbound(s.id, from.Addr())
		}
	}
	ev := candEvent{local: s.local, remote: from, fam: s.fam, at: at, epoch: h.Aux, peerSock: h.Sock, slot: t.Slot, paths: t.Paths}
	switch {
	case known:
		ev.ckind = kind
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
	t := udpwire.TLVs{Observed: to, RxCount: uint32(rt.punch.rx.Load()), HasRx: true}
	_ = rt.sender.Send(rt.g.Context(), s, to, &h, &t, sendOpt{class: classReply, stage: txReply})
}

// noteICMP counts an ICMP soft signal on socket s and lets the
// prober see it while probing.
func (rt *runtime) noteICMP(s *udpSock) {
	fs := rt.fam(s.fam)
	if pr := fs.prober.Load(); pr != nil {
		pr.NoteUnreachable(s.id)
	}
	st := rt.punch
	if !st.active.Load() {
		return
	}
	st.mu.Lock()
	rs := st.statsFor(s.fam)
	rs.icmp++
	st.icmpMax = max(st.icmpMax, rs.icmp)
	st.mu.Unlock()
}

// onPeerSeen consumes a relayed peer_seen: the peer received our packet
// from socket a.Sock aimed at our target a.Cand, and saw it come from
// a.Remote. The remote is evidence only — never a target. It feeds
// the observation table (drift, traits correction) and, when the peer still
// has not been heard 200 ms later, a follow-up of three punches on the
// exact (socket, target) pair that got through.
func (rt *runtime) onPeerSeen(a protocol.Assist, at time.Time) {
	st := rt.punch
	w := rt.fam(a.Family).worker
	if w == nil {
		return
	}
	rt.fam(a.Family).cnt.peerSeenUs.Store(true)
	st.mu.Lock()
	st.statsFor(a.Family).peerSeenUs = true
	st.peerSeen = true
	target, known := st.cands[sockCand{a.Sock, a.Cand}]
	if known {
		st.hit[target] = true
	}
	st.mu.Unlock()
	if !known {
		return
	}
	if tab := w.fs.table(); tab != nil && a.Remote.IsValid() {
		k := nat.PointKey{Socket: a.Sock, Source: nat.SourcePeer, Peer: target}
		if tab.Record(k, a.Remote, at.Sub(rt.startAt), 0, 0) {
			st.mu.Lock()
			st.statsFor(a.Family).drift = true
			st.mu.Unlock()
			rt.progress(progressEvent{stage: stageDriftDetected, status: protocol.StatusInfo, family: a.Family})
		}
		rt.traitsSource[famIndex(a.Family)].Store(true)
	}
	rt.followUp(a.Family, a.Sock, target)
}

func containsAddr(list []netip.AddrPort, a netip.AddrPort) bool {
	for _, x := range list {
		if x == a {
			return true
		}
	}
	return false
}
