package nattest

import (
	"maps"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// statsWindow is the sliding window of DistinctDstPortsPerIP10s and
	// MaxConsecutiveRun, the 10 s window of holepunch's send budget rules.
	statsWindow = 10 * time.Second
	// shapeBytes bounds the payload prefix compared for ConstantOffsets; it
	// covers every packet the library sends.
	shapeBytes = 2048
	// closedSocketsKept bounds the closed sockets HostStats.Sockets keeps,
	// so that a long test does not accumulate them without limit.
	closedSocketsKept = 1024
)

// hostCounters is the mutable state behind HostStats.
type hostCounters struct {
	recv, bytesRecv             atomic.Uint64
	noSocket, inboxFull         atomic.Uint64
	afterHandover               atomic.Uint64
	injectedWrite, injectedBind atomic.Uint64

	mu              sync.Mutex // guards the fields below
	sent, bytesSent uint64
	pps100, pps1s   countWindow
	peak100, peak1s int
	perIP           map[netip.Addr]*dstTrack
	maxDistinct     int
	maxRun          int
	firstSend       time.Duration
	hasFirst        bool
	firstByte       [256]uint64
	lens            map[int]uint64
	opened, closed  uint64
	byPurpose       map[string]uint64
	sockets         []*socketRecord // opening order
	closedKept      int             // closed records in sockets
}

// dstTrack follows the send sequence towards one destination IP.
type dstTrack struct {
	ports *portWindow
	run   runState
	first time.Duration
}

// socketRecord is the mutable state behind one SocketStats; it outlives its
// socket so that a test can inspect a session after the library closed it.
// It is guarded by hostCounters.mu.
type socketRecord struct {
	local     netip.AddrPort
	purpose   string
	closed    bool
	handover  bool
	hopLimit  int
	packets   uint64
	bytes     uint64
	firstByte [256]uint64
	lens      map[int]uint64
	shape     constScan
	// The flows of the socket by destination, with whether a packet that
	// is no STUN message went out on each (STUN openers).
	flows          map[netip.AddrPort]bool
	stun           uint64
	plainFirst     int
	stunAfterPlain uint64
}

// constScan finds the payload offsets at which every packet carries the same
// byte. After the first packet it keeps a reference copy and the offsets
// that still agree; every later packet can only remove offsets, and once
// none is left (after two or three random packets) the scan costs nothing.
type constScan struct {
	seen  bool
	ref   []byte
	fixed []uint16
}

func (s *constScan) add(p []byte) {
	if !s.seen {
		s.seen = true
		s.ref = slices.Clone(p[:min(len(p), shapeBytes)])
		s.fixed = make([]uint16, len(s.ref))
		for i := range s.fixed {
			s.fixed[i] = uint16(i)
		}
		return
	}
	if len(s.fixed) == 0 {
		return
	}
	keep := s.fixed[:0]
	for _, off := range s.fixed {
		if int(off) < len(p) && p[off] == s.ref[off] {
			keep = append(keep, off)
		}
	}
	s.fixed = keep
	if len(keep) == 0 {
		s.ref, s.fixed = nil, nil
	}
}

func (s *constScan) offsets(packets uint64) []int {
	if packets < 2 || len(s.fixed) == 0 {
		return nil
	}
	out := make([]int, len(s.fixed))
	for i, off := range s.fixed {
		out[i] = int(off)
	}
	return out
}

func (s *hostCounters) init() {
	s.pps100.win = 100 * time.Millisecond
	s.pps1s.win = time.Second
	s.perIP = make(map[netip.Addr]*dstTrack)
	s.lens = make(map[int]uint64)
	s.byPurpose = make(map[string]uint64)
}

// openSocket registers a new socket and returns its record.
func (s *hostCounters) openSocket(local netip.AddrPort, purpose string) *socketRecord {
	r := &socketRecord{local: local, purpose: purpose, lens: make(map[int]uint64), flows: make(map[netip.AddrPort]bool)}
	s.mu.Lock()
	s.opened++
	s.byPurpose[purpose]++
	s.sockets = append(s.sockets, r)
	s.mu.Unlock()
	return r
}

// closeSocket marks r closed and forgets the oldest closed record beyond
// closedSocketsKept.
func (s *hostCounters) closeSocket(r *socketRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed++
	r.closed = true
	s.closedKept++
	if s.closedKept <= closedSocketsKept {
		return
	}
	if i := slices.IndexFunc(s.sockets, func(r *socketRecord) bool { return r.closed }); i >= 0 {
		s.sockets = slices.Delete(s.sockets, i, i+1)
		s.closedKept--
	}
}

func (s *hostCounters) setHopLimit(r *socketRecord, hops int) {
	s.mu.Lock()
	r.hopLimit = hops
	s.mu.Unlock()
}

func (s *hostCounters) markHandover(r *socketRecord) {
	s.mu.Lock()
	r.handover = true
	s.mu.Unlock()
}

// recordSend accounts a packet accepted by WriteTo on the socket of r. It
// reads the clock under the lock, so that the sliding windows see the sends
// of concurrent sockets in time order.
func (s *hostCounters) recordSend(n *Network, r *socketRecord, dst netip.AddrPort, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := n.now()
	s.sent++
	s.bytesSent += uint64(len(data))
	s.peak100 = max(s.peak100, s.pps100.add(now))
	s.peak1s = max(s.peak1s, s.pps1s.add(now))
	if !s.hasFirst {
		s.hasFirst, s.firstSend = true, now
	}
	tr := s.perIP[dst.Addr()]
	if tr == nil {
		tr = &dstTrack{ports: newPortWindow(statsWindow), first: now}
		s.perIP[dst.Addr()] = tr
	}
	s.maxDistinct = max(s.maxDistinct, tr.ports.add(now, dst.Port()))
	s.maxRun = max(s.maxRun, tr.run.add(now, dst.Port(), statsWindow))
	s.lens[len(data)]++
	r.packets++
	r.bytes += uint64(len(data))
	r.lens[len(data)]++
	stun := IsSTUN(data)
	plain, known := r.flows[dst]
	switch {
	case !known && !stun:
		r.plainFirst++
	case stun && plain:
		r.stunAfterPlain++
	}
	r.flows[dst] = plain || !stun
	if stun {
		// A STUN header is the standard's, the same in every STUN packet
		// of the Internet: the packet shape (first bytes, constant offsets)
		// is judged on the other packets.
		r.stun++
		return
	}
	if len(data) > 0 {
		s.firstByte[data[0]]++
		r.firstByte[data[0]]++
	}
	r.shape.add(data)
}

func (s *hostCounters) snapshot(n *Network) HostStats {
	st := HostStats{
		PacketsRecv:         s.recv.Load(),
		BytesRecv:           s.bytesRecv.Load(),
		WritesAfterHandover: s.afterHandover.Load(),
		InjectedWriteErrors: s.injectedWrite.Load(),
		InjectedBindErrors:  s.injectedBind.Load(),
		DroppedNoSocket:     s.noSocket.Load(),
		DroppedInboxFull:    s.inboxFull.Load(),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st.PacketsSent = s.sent
	st.BytesSent = s.bytesSent
	st.PeakPPS100ms = s.peak100
	st.PeakPPS1s = s.peak1s
	st.DistinctDstPortsPerIP10s = s.maxDistinct
	st.MaxConsecutiveRun = s.maxRun
	if s.hasFirst {
		st.FirstSendAt = n.wall(s.firstSend)
	}
	st.FirstSendTo = make(map[netip.Addr]time.Time, len(s.perIP))
	for ip, tr := range s.perIP {
		st.FirstSendTo[ip] = n.wall(tr.first)
	}
	st.SocketsOpened = s.opened
	st.SocketsClosed = s.closed
	st.SocketsByPurpose = maps.Clone(s.byPurpose)
	st.FirstByteHistogram = s.firstByte
	st.LenHistogram = maps.Clone(s.lens)
	st.Sockets = make([]SocketStats, len(s.sockets))
	for i, r := range s.sockets {
		st.Sockets[i] = SocketStats{
			Local:              r.local,
			Purpose:            r.purpose,
			Closed:             r.closed,
			Handover:           r.handover,
			HopLimit:           r.hopLimit,
			PacketsSent:        r.packets,
			BytesSent:          r.bytes,
			FirstByteHistogram: r.firstByte,
			LenHistogram:       maps.Clone(r.lens),
			ConstantOffsets:    r.shape.offsets(r.packets - r.stun),
			STUNPackets:        r.stun,
			Flows:              len(r.flows),
			PlainFirst:         r.plainFirst,
			STUNAfterPlain:     r.stunAfterPlain,
		}
	}
	return st
}
