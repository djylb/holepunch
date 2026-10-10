package holepunch

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/internal/netaddr"
	"github.com/djylb/holepunch/internal/udpicmp"
	"github.com/djylb/holepunch/protocol"
)

// Socket limits.
const (
	primaryRecvBuffer = 1 << 20   // primary, second and sibling sockets
	extraRecvBuffer   = 256 << 10 // round sockets only receive replies
	readBufferSize    = 2048      // larger than any holepunch datagram (1069 B)
	writeDeadline     = 100 * time.Millisecond
	extraPortLo       = 20000 // extra sockets bind a random port in [20000, 60000) first
	extraPortHi       = 60000
	extraBindTries    = 3
	firstExtraIndex   = 5   // round and birthday sockets use indexes 5–125 (internal/nat)
	maxSocketIndex    = 125 // the last index the 7-bit sock field leaves to round sockets
	winnerReadJoin    = time.Second
	writeTurnWait     = time.Second
	preRateBurst      = 8000 // per-socket pre-AEAD token bucket
	preRatePerSec     = 4000
)

// Fault-injection points of the socket layer.
const (
	fiProbeBind      = "probe.bind"
	fiReadloopPacket = "readloop.packet"
)

// aLongTimeAgo is the past deadline that interrupts a blocked read.
var aLongTimeAgo = time.Unix(1, 0)

var (
	errDetached  = errors.New("holepunch: socket handed over")
	errNoSockets = errors.New("holepunch: socket budget exhausted")
)

// udpSock is one socket of the session. The session group owns its conn
// until the handover disowns the winner. Its read loop is the only reader;
// every write goes through the sender, which holds the socket's write turn
// for the duration of the hop-limit change and the write.
type udpSock struct {
	conn  net.PacketConn
	fam   protocol.Family
	id    uint8 // header sock value: family<<7 | index
	local netip.AddrPort

	turn     chan struct{} // the write turn: one write (and hop change) at a time
	detached bool          // guarded by the turn
	hop      hopCtl
	curHop   int // guarded by the turn; 0 = the value recorded at creation
	noLowTTL atomic.Bool

	// The flow opener (opener.go): the session's, nil when it is off; the
	// remotes this socket opened and the buffer of an opener being written,
	// both guarded by the turn.
	op     *opener
	opened map[netip.AddrPort]struct{}
	obuf   []byte

	stopping atomic.Bool   // set by stopRead: a read timeout now ends the loop
	readDone chan struct{} // closed when the read loop returns

	// pre-AEAD rate limit, touched by the read loop only
	rateTokens float64
	rateAt     time.Time
}

// hopCtl sets the unicast TTL of one socket: through HopLimiter when the conn
// implements it, else through syscall.Conn. orig is the value found at
// creation, restored before the handover.
type hopCtl struct {
	hl     HopLimiter
	rc     syscall.RawConn
	panics *atomic.Int64 // the session's callback panics, which a panicking HopLimiter adds to
	orig   int
	v6     bool
	ok     bool
}

func newHopCtl(conn net.PacketConn, v6 bool, panics *atomic.Int64) hopCtl {
	h := hopCtl{v6: v6, panics: panics}
	if hl, ok := conn.(HopLimiter); ok {
		h.hl, h.ok = hl, true
		return h
	}
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return h
	}
	var err error
	if p := life.Safe("syscallconn", func() { h.rc, err = sc.SyscallConn() }); p != nil || err != nil {
		if p != nil {
			panics.Add(1)
		}
		return hopCtl{v6: v6, panics: panics}
	}
	if h.orig, err = rawHopLimit(h.rc, v6); err != nil {
		return hopCtl{v6: v6, panics: panics}
	}
	h.ok = true
	return h
}

// set applies hops; 0 restores the original value. A panic in a user
// HopLimiter is an error of the call, counted as a callback panic.
func (h *hopCtl) set(hops int) error {
	if !h.ok {
		return errLowTTLUnavailable
	}
	if h.hl != nil {
		var err error
		if p := life.Safe("hoplimiter", func() { err = h.hl.SetHopLimit(hops) }); p != nil {
			h.panics.Add(1)
			return p
		}
		return err
	}
	v := hops
	if hops == 0 {
		v = h.orig
	}
	return setRawHopLimit(h.rc, h.v6, v)
}

var errLowTTLUnavailable = errors.New("holepunch: low TTL unavailable")

// acquire takes the write turn; it fails when ctx ends first.
func (s *udpSock) acquire(ctx context.Context) error {
	select {
	case s.turn <- struct{}{}:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func (s *udpSock) releaseTurn() { <-s.turn }

// write sends pkt to `to` with hops (0: normal TTL) under the write turn,
// as an opener when it is the first datagram of the flow (opener.go).
// wrapped reports that it left as one.
func (s *udpSock) write(ctx context.Context, pkt []byte, to netip.AddrPort, hops int) (wrapped bool, err error) {
	if err := s.acquire(ctx); err != nil {
		return false, err
	}
	defer s.releaseTurn()
	if s.detached {
		return false, errDetached
	}
	if hops > 0 && s.noLowTTL.Load() {
		hops = 0
	}
	if hops != s.curHop {
		if herr := s.hop.set(hops); herr != nil {
			if hops > 0 {
				s.noLowTTL.Store(true)
			}
			hops = s.curHop
		} else {
			s.curHop = hops
		}
	}
	if err := s.conn.SetWriteDeadline(time.Now().Add(writeDeadline)); err != nil {
		return false, err
	}
	out, wrapped := s.form(pkt, to)
	if w, ok := s.conn.(interface {
		WriteToUDPAddrPort([]byte, netip.AddrPort) (int, error)
	}); ok {
		_, err = w.WriteToUDPAddrPort(out, to)
	} else {
		_, err = s.conn.WriteTo(out, netaddr.UDPAddr(to))
	}
	if err == nil && hops == 0 {
		s.noteOpened(to)
	}
	return wrapped, err
}

// detach marks the socket handed over (finish step 1): it waits for a write
// in progress, then refuses every later one. It reports false when a write
// did not finish within writeTurnWait.
func (s *udpSock) detach() bool {
	t := time.NewTimer(writeTurnWait)
	defer t.Stop()
	select {
	case s.turn <- struct{}{}:
	case <-t.C:
		return false
	}
	s.detached = true
	<-s.turn
	return true
}

// stopRead interrupts the read loop of the winning socket (finish step 2):
// the past deadline wakes the blocked read and the stopping flag makes the
// loop return instead of clearing it.
func (s *udpSock) stopRead() {
	s.stopping.Store(true)
	_ = s.conn.SetReadDeadline(aLongTimeAgo)
}

// read reads one datagram with its canonical source.
func (s *udpSock) read(buf []byte) (int, netip.AddrPort, error) {
	if r, ok := s.conn.(interface {
		ReadFromUDPAddrPort([]byte) (int, netip.AddrPort, error)
	}); ok {
		n, from, err := r.ReadFromUDPAddrPort(buf)
		return n, netaddr.Canon(from), err
	}
	n, a, err := s.conn.ReadFrom(buf)
	from, _ := netaddr.FromNetAddr(a)
	return n, from, err
}

// readLoop is the socket's only reader (no polling, no AfterFunc).
// A losing socket's loop ends when the session group closes the socket;
// the winner's ends on stopRead. A read timeout the library did not ask for
// is cleared and counted. An ICMP report — Windows delivers them on
// unconnected sockets too, as WSAECONNRESET or WSAENETRESET — is a soft
// signal about an earlier datagram, never a reason to stop reading. Any
// other error ends the loop and removes the socket from the candidates.
func (s *udpSock) readLoop(rt *runtime) {
	defer close(s.readDone)
	buf := make([]byte, readBufferSize)
	for {
		n, from, err := s.read(buf)
		if err != nil {
			var ne net.Error
			switch {
			case errors.As(err, &ne) && ne.Timeout() || errors.Is(err, os.ErrDeadlineExceeded):
				if s.stopping.Load() {
					return
				}
				_ = s.conn.SetReadDeadline(time.Time{})
				continue
			case errors.Is(err, net.ErrClosed):
				return
			case udpicmp.IsReport(err):
				rt.noteICMP(s)
				continue
			}
			rt.readFailed(s)
			return
		}
		if s.stopping.Load() {
			return
		}
		if faultinject.Point(fiReadloopPacket) != nil {
			continue
		}
		rt.dispatch(s, buf[:n], from)
	}
}

// preRateAllow is the per-socket pre-AEAD token bucket; read loop only.
func (s *udpSock) preRateAllow(now time.Time) bool {
	if s.rateAt.IsZero() {
		s.rateAt, s.rateTokens = now, preRateBurst
	}
	if dt := now.Sub(s.rateAt); dt > 0 {
		s.rateTokens = min(preRateBurst, s.rateTokens+dt.Seconds()*preRatePerSec)
		s.rateAt = now
	}
	if s.rateTokens < 1 {
		return false
	}
	s.rateTokens--
	return true
}

// socketPool holds every socket of the session, indexed by family, role in
// the session and local address. It enforces the socket budget.
type socketPool struct {
	rt *runtime

	mu        sync.Mutex
	all       []*udpSock
	byLocal   map[netip.AddrPort]*udpSock
	extras    [2][]*udpSock
	nextIndex [2]uint8
	limit     int // MaxSockets of the merged policy, then of the session budget
	outbound  [2]netip.Addr
}

func famIndex(f protocol.Family) int {
	if f == protocol.FamilyUDP6 {
		return 1
	}
	return 0
}

func famNetwork(f protocol.Family) string { return string(f) }

func newSocketPool(rt *runtime, limit int) *socketPool {
	return &socketPool{rt: rt, byLocal: map[netip.AddrPort]*udpSock{}, limit: limit,
		nextIndex: [2]uint8{firstExtraIndex, firstExtraIndex}}
}

// setLimit lowers the socket budget (session budget after the summary).
func (p *socketPool) setLimit(n int) {
	p.mu.Lock()
	p.limit = n
	p.mu.Unlock()
}

// reserve takes one socket of the budget.
func (p *socketPool) reserve() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.all) >= p.limit {
		return false
	}
	p.all = append(p.all, nil) // placeholder, replaced or removed by commit
	return true
}

func (p *socketPool) unreserve() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := len(p.all) - 1; i >= 0; i-- {
		if p.all[i] == nil {
			p.all = append(p.all[:i], p.all[i+1:]...)
			return
		}
	}
}

func (p *socketPool) commit(s *udpSock) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, x := range p.all {
		if x == nil {
			p.all[i] = s
			break
		}
	}
	p.byLocal[s.local] = s
}

// open binds one socket, records its concrete local address and hop control,
// hands it to the session group and starts its read loop. A typed-nil conn
// from the Network is a failed bind.
func (p *socketPool) open(ctx context.Context, fam protocol.Family, laddr netip.AddrPort, purpose string, index uint8, rcvbuf int) (*udpSock, error) {
	if !p.reserve() {
		return nil, errNoSockets
	}
	rt := p.rt
	conn, err := p.listen(ctx, fam, laddr, purpose)
	if err != nil {
		p.unreserve()
		return nil, err
	}
	name := purpose + ":" + string(fam) + ":" + strconv.Itoa(int(index))
	if !rt.g.Own(name, conn) {
		p.unreserve()
		return nil, net.ErrClosed
	}
	local := p.concreteLocal(ctx, fam, conn)
	if sb, ok := conn.(interface{ SetReadBuffer(int) error }); ok {
		if pe := life.Safe("setreadbuffer", func() { _ = sb.SetReadBuffer(rcvbuf) }); pe != nil {
			rt.cnt.callbackPanics.Add(1)
		}
	}
	s := &udpSock{
		conn: conn, fam: fam, id: nat.SocketID(fam, index), local: local,
		turn: make(chan struct{}, 1), readDone: make(chan struct{}), op: rt.opener,
	}
	s.hop = newHopCtl(conn, fam == protocol.FamilyUDP6, &rt.cnt.callbackPanics)
	p.commit(s)
	rt.fam(fam).cnt.sockets.Add(1)
	if !rt.g.Go("udp-read:"+name, func(context.Context) { s.readLoop(rt) }) {
		close(s.readDone)
	}
	return s, nil
}

// listen calls Network.ListenPacket in a recover boundary.
func (p *socketPool) listen(ctx context.Context, fam protocol.Family, laddr netip.AddrPort, purpose string) (net.PacketConn, error) {
	if err := faultinject.Point(fiProbeBind); err != nil {
		return nil, err
	}
	var conn net.PacketConn
	var err error
	if pe := life.Safe("network.listenpacket", func() {
		conn, err = p.rt.netw.ListenPacket(ctx, famNetwork(fam), laddr, purpose)
	}); pe != nil {
		p.rt.cnt.callbackPanics.Add(1)
		return nil, pe
	}
	if err != nil {
		return nil, err
	}
	if life.IsNil(conn) {
		return nil, errNilConn
	}
	return conn, nil
}

var errNilConn = errors.New("holepunch: Network.ListenPacket returned a nil conn")

// concreteLocal returns the socket's local address with a wildcard replaced
// by the family's outbound address (Result.LocalAddr is always concrete).
func (p *socketPool) concreteLocal(ctx context.Context, fam protocol.Family, conn net.PacketConn) netip.AddrPort {
	var la net.Addr
	if pe := life.Safe("localaddr", func() { la = conn.LocalAddr() }); pe != nil {
		p.rt.cnt.callbackPanics.Add(1)
	}
	ap, _ := netaddr.FromNetAddr(la)
	if ap.Addr().IsValid() && !ap.Addr().IsUnspecified() {
		return ap
	}
	return netip.AddrPortFrom(p.outboundAddr(ctx, fam), ap.Port())
}

// outboundAddr asks the Network once per family for the outbound address.
func (p *socketPool) outboundAddr(ctx context.Context, fam protocol.Family) netip.Addr {
	i := famIndex(fam)
	p.mu.Lock()
	a := p.outbound[i]
	p.mu.Unlock()
	if a.IsValid() {
		return a
	}
	var err error
	if pe := life.Safe("network.outboundaddr", func() { a, err = p.rt.netw.OutboundAddr(ctx, famNetwork(fam)) }); pe != nil || err != nil {
		if pe != nil {
			p.rt.cnt.callbackPanics.Add(1)
		}
		return netip.Addr{}
	}
	a = a.Unmap().WithZone("")
	p.mu.Lock()
	p.outbound[i] = a
	p.mu.Unlock()
	return a
}

// byID returns the socket of family fam with the header id sock.
func (p *socketPool) byID(fam protocol.Family, sock uint8) *udpSock {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.all {
		if s != nil && s.fam == fam && s.id == sock {
			return s
		}
	}
	return nil
}

// ownsPort reports whether a socket of family fam is bound to port.
func (p *socketPool) ownsPort(fam protocol.Family, port uint16) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.all {
		if s != nil && s.fam == fam && s.local.Port() == port {
			return true
		}
	}
	return false
}

// byAddr returns the socket bound to local.
func (p *socketPool) byAddr(local netip.AddrPort) *udpSock {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.byLocal[local]
}

// roundSockets returns the n sockets a round of family fam initiates from: the
// primary first, then extra sockets, binding the missing ones on the primary's
// IP (a random port in [20000, 60000) first, then any). Sockets it could not
// obtain are reported in bindFailed and the round runs with fewer; three bind
// failures in a row stop the attempt.
func (p *socketPool) roundSockets(ctx context.Context, primary *udpSock, n int, purpose string) (socks []*udpSock, bindFailed int) {
	socks = append(socks, primary)
	fi := famIndex(primary.fam)
	for fails := 0; len(socks) < n && fails < extraBindTries; {
		p.mu.Lock()
		var s *udpSock
		if k := len(socks) - 1; k < len(p.extras[fi]) {
			s = p.extras[fi][k]
		}
		idx := p.nextIndex[fi]
		if s == nil && idx <= maxSocketIndex {
			p.nextIndex[fi]++
		}
		p.mu.Unlock()
		if s == nil {
			if idx > maxSocketIndex {
				break
			}
			var err error
			if s, err = p.openExtra(ctx, primary, idx, purpose); err != nil {
				if errors.Is(err, errNoSockets) || errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
					break
				}
				fails++
				continue
			}
			p.mu.Lock()
			p.extras[fi] = append(p.extras[fi], s)
			p.mu.Unlock()
		}
		fails = 0
		socks = append(socks, s)
	}
	return socks, n - len(socks)
}

// openExtra binds an extra round socket with the index idx.
func (p *socketPool) openExtra(ctx context.Context, primary *udpSock, idx uint8, purpose string) (*udpSock, error) {
	ip := primary.local.Addr()
	for range extraBindTries {
		port := p.rt.pace.portIn(extraPortLo, extraPortHi)
		s, err := p.open(ctx, primary.fam, netip.AddrPortFrom(ip, port), purpose, idx, extraRecvBuffer)
		if err == nil || errors.Is(err, errNoSockets) || errors.Is(err, net.ErrClosed) {
			return s, err
		}
	}
	return p.open(ctx, primary.fam, netip.AddrPortFrom(ip, 0), purpose, idx, extraRecvBuffer)
}

// freshSocket binds a fresh socket of one round on the primary's IP at
// port, with the next round-socket index. It holds a place in the
// socket budget until release.
func (p *socketPool) freshSocket(ctx context.Context, primary *udpSock, port uint16) (*udpSock, error) {
	idx, err := p.takeIndex(primary.fam)
	if err != nil {
		return nil, err
	}
	return p.open(ctx, primary.fam, netip.AddrPortFrom(primary.local.Addr(), port), PurposeFresh, idx, extraRecvBuffer)
}

// pacedSocket binds a paced socket of one round (FamilySide.OpenPerSec)
// like an extra round socket, with the next round-socket index, but
// for that round only: it is not kept for later rounds and holds a place in
// the socket budget until release.
func (p *socketPool) pacedSocket(ctx context.Context, primary *udpSock, purpose string) (*udpSock, error) {
	idx, err := p.takeIndex(primary.fam)
	if err != nil {
		return nil, err
	}
	return p.openExtra(ctx, primary, idx, purpose)
}

// takeIndex takes the next round-socket index of family fam; errNoSockets
// once the header's index space is spent.
func (p *socketPool) takeIndex(fam protocol.Family) (uint8, error) {
	fi := famIndex(fam)
	p.mu.Lock()
	defer p.mu.Unlock()
	idx := p.nextIndex[fi]
	if idx > maxSocketIndex {
		return 0, errNoSockets
	}
	p.nextIndex[fi]++
	return idx, nil
}

// sandwichHelper binds a sandwich helper socket (index 4) for one family
// round on the primary's IP: a new internal endpoint, so that both probes of
// the round map anew on any NAT. It holds a place in the socket budget
// until release; nil when the
// budget or the bind refuses it.
func (p *socketPool) sandwichHelper(ctx context.Context, primary *udpSock) *udpSock {
	s, err := p.open(ctx, primary.fam, netip.AddrPortFrom(primary.local.Addr(), 0), PurposeProbe, nat.IndexSandwich, extraRecvBuffer)
	if err != nil {
		return nil
	}
	return s
}

// release closes s before the session ends — a round's sandwich helper — and
// gives its place in the socket budget back. Its read loop ends on the
// close. A socket the closing session group already took is left to it.
func (p *socketPool) release(s *udpSock) {
	p.mu.Lock()
	p.all = slices.DeleteFunc(p.all, func(x *udpSock) bool { return x == s })
	if p.byLocal[s.local] == s {
		delete(p.byLocal, s.local)
	}
	p.mu.Unlock()
	if !p.rt.g.Disown(s.conn) {
		return
	}
	if pe := life.Safe("socket.close", func() { _ = s.conn.Close() }); pe != nil {
		p.rt.cnt.callbackPanics.Add(1)
	}
}
