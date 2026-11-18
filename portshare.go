package holepunch

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/netaddr"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/udpsock"
)

// ErrLocalPortUnavailable is reached through Error.Err (errors.Is) when the
// port Options.LocalPort pins cannot carry the session: another socket holds
// it or the system refuses it to this process, or — with SharedPorts — a
// confirmed path would run between the same two endpoints as a path another
// session handed over on the shared socket. The session fails with Reason
// local_port_bind_failed; the caller falls back by punching again with
// LocalPort 0.
var ErrLocalPortUnavailable = errors.New("holepunch: local port unavailable")

// Port-share limits.
const (
	shareQueue     = 256  // datagrams queued per member before the newest is dropped
	shareMaxWrites = 4096 // remotes a member remembers having written to
)

// SharedPorts lets concurrent sessions that pin the same Options.LocalPort
// share one socket per family and local address instead of each binding the
// port. Every session that names the same SharedPorts and the same Network
// joins the socket the first one bound; the socket closes when the last
// session using it ends, or when the last Session it was handed over to
// closes.
//
// The shared socket's single reader gives each datagram to one session: to
// the punching session whose key opens it, else to the session whose
// handed-over path runs to its source, else to the punching sessions that
// wrote to its source (a STUN
// server's answer, an upper-layer packet ahead of the handover). A
// session's packets carry nothing that names it on the wire. A Session
// handed over on a shared socket receives only the datagrams of its
// confirmed remotes; it owns a member of the socket, not the socket, so its
// PacketConn is the library's member conn rather than what
// Network.ListenPacket returned.
//
// Sharing needs a comparable Network value (SystemNetwork's is, and so is
// a pointer); with one that is not, every session binds the port itself and
// a second one at the same time fails with ErrLocalPortUnavailable. The
// member conn is no *net.UDPConn, and after the handover it does not
// follow the peer to a new address: a datagram from anywhere but the
// confirmed remotes does not reach it.
//
// The zero value is ready to use; a SharedPorts must not be copied after
// first use. It is safe for concurrent use.
type SharedPorts struct {
	mu    sync.Mutex
	ports map[shareKey]*portShare
}

// shareKey names one shared socket. netw is the sessions' Network, which
// must be comparable for sharing (shareable).
type shareKey struct {
	netw    Network
	network string
	laddr   netip.AddrPort
}

// shareable reports whether sessions on netw can share sockets: its value
// compares with == without panicking.
func shareable(netw Network) bool { return reflect.ValueOf(netw).Comparable() }

// portShare is one shared socket: its group owns the conn and runs the
// reader; its members are the sessions' views of it. It is in the registry
// from its creation until its conn is closed (retire), so a session never
// binds the port while the library still holds it.
type portShare struct {
	sp    *SharedPorts
	key   shareKey
	conn  net.PacketConn // set by bind on success, before bound closes
	local net.Addr       // conn's local address, read once by bind
	g     *life.Group
	bound chan struct{} // closed when bind is done
	gone  chan struct{} // closed by retire once the conn is closed and the share forgotten
	bufs  sync.Pool     // *[readBufferSize]byte

	turn   chan struct{} // the write turn across members: one hop change and write at a time
	hop    hopCtl
	curHop int // guarded by the turn
	panics atomic.Int64

	mu      sync.Mutex
	members []*sharedConn // replaced, never modified in place
	closing bool          // no member joins any more

	retired  atomic.Bool   // retire ran or runs: the first caller does it, others return at once
	readDone chan struct{} // closed when the reader returns
	dead     chan struct{} // closed when the reader stopped on an error: readErr is set
	readErr  error

	// the reader's own
	scratch  []*sharedConn // the members a datagram goes to
	open     []*sharedConn // the members still punching
	classify bucket        // classification trials, a pre-AEAD limit
}

// join returns a member of the shared socket on laddr, binding it through
// netw when no session holds it. accept is the member's classifier: whether
// a datagram is one of its session's. Sessions that join while the socket
// is being bound wait for that bind; when it fails they bind themselves, so
// each gets its own error. A socket being closed is waited for, then bound
// anew.
func (sp *SharedPorts) join(ctx context.Context, netw Network, network string, laddr netip.AddrPort, accept func([]byte) bool) (*sharedConn, error) {
	key := shareKey{netw: netw, network: network, laddr: laddr}
	for {
		sp.mu.Lock()
		sh := sp.ports[key]
		creator := sh == nil
		if creator {
			sh = &portShare{sp: sp, key: key, bound: make(chan struct{}), gone: make(chan struct{})}
			if sp.ports == nil {
				sp.ports = map[shareKey]*portShare{}
			}
			sp.ports[key] = sh
		}
		sp.mu.Unlock()
		if creator {
			if err := sh.bind(ctx); err != nil {
				sp.forget(sh)
				close(sh.gone)
				return nil, err
			}
		} else if !waitFor(ctx, sh.bound) {
			return nil, context.Cause(ctx)
		}
		if sh.conn == nil { // the creator's bind failed: try ours
			continue
		}
		if c := sh.add(accept); c != nil {
			return c, nil
		}
		// The socket is closing: wait until it is closed and bind it anew.
		if !waitFor(ctx, sh.gone) {
			return nil, context.Cause(ctx)
		}
	}
}

// waitFor waits for ch to close; false when ctx ends first.
func waitFor(ctx context.Context, ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	case <-ctx.Done():
		return isClosed(ch)
	}
}

// bind binds the socket and starts its reader; bound is closed either way,
// conn set only on success. It calls the Network outside every lock.
func (sh *portShare) bind(ctx context.Context) error {
	defer close(sh.bound)
	var conn net.PacketConn
	var err error
	listen := func() { conn, err = sh.key.netw.ListenPacket(ctx, sh.key.network, sh.key.laddr, PurposeProbe) }
	if pe := life.Safe("network.listenpacket", listen); pe != nil {
		return pe
	}
	if err != nil {
		return err
	}
	if life.IsNil(conn) {
		return errNilConn
	}
	_ = life.Safe("localaddr", func() { sh.local = conn.LocalAddr() })
	if sb, ok := conn.(interface{ SetReadBuffer(int) error }); ok {
		_ = life.Safe("setreadbuffer", func() { _ = sb.SetReadBuffer(primaryRecvBuffer) })
	}
	sh.g = life.New(context.Background())
	sh.bufs.New = func() any { return new([readBufferSize]byte) }
	sh.turn = make(chan struct{}, 1)
	sh.readDone = make(chan struct{})
	sh.dead = make(chan struct{})
	sh.classify = newBucket(preRatePerSec, preRateBurst)
	sh.hop = newHopCtl(conn, &sh.panics)
	sh.g.Own("shared", &connOwner{conn: conn})
	sh.conn = conn
	if !sh.g.Go("udp-read:shared", func(context.Context) { sh.readLoop() }) {
		close(sh.readDone)
	}
	return nil
}

// forget removes sh from the registry if it is still the socket of its key.
func (sp *SharedPorts) forget(sh *portShare) {
	sp.mu.Lock()
	if sp.ports[sh.key] == sh {
		delete(sp.ports, sh.key)
	}
	sp.mu.Unlock()
}

// add makes a new member; nil when the socket is closing.
func (sh *portShare) add(accept func([]byte) bool) *sharedConn {
	c := &sharedConn{sh: sh, accept: accept, q: make(chan shareItem, shareQueue),
		closed: make(chan struct{}), rd: newDeadline()}
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if sh.closing {
		return nil
	}
	sh.members = append(slices.Clip(sh.members), c)
	return c
}

// remove takes c out of the members; the last one retires the socket.
func (sh *portShare) remove(c *sharedConn) {
	sh.mu.Lock()
	sh.members = slices.DeleteFunc(slices.Clone(sh.members), func(x *sharedConn) bool { return x == c })
	last := len(sh.members) == 0
	if last {
		sh.closing = true
	}
	sh.mu.Unlock()
	if last {
		sh.retire(false)
		_ = sh.g.Close(joinBound) // after a reader retire: the group's own bookkeeping
	}
}

// retire takes the socket out of service once: no member joins any more,
// the conn is closed — by the group, joining the reader, or by the reader
// itself after a read error — and only then is it forgotten, so that the
// next session binds the port anew. A second call returns at once: the
// reader must never wait for a retire that joins it.
func (sh *portShare) retire(fromReader bool) {
	if !sh.retired.CompareAndSwap(false, true) {
		return
	}
	sh.mu.Lock()
	sh.closing = true
	sh.mu.Unlock()
	if fromReader {
		_ = life.Safe("socket.close", func() { _ = sh.conn.Close() })
	} else {
		_ = sh.g.Close(joinBound)
	}
	sh.sp.forget(sh)
	close(sh.gone)
}

// readLoop is the socket's only reader. It routes every datagram (route)
// and hands ICMP reports on (report); a read timeout nobody asked for is
// cleared, a datagram larger than the buffer dropped. Any other error ends
// it, every member's reads and the socket.
func (sh *portShare) readLoop() {
	defer close(sh.readDone)
	for {
		b, _ := sh.bufs.Get().(*[readBufferSize]byte)
		n, from, err := sh.read(b[:])
		if err != nil {
			sh.bufs.Put(b)
			var ne net.Error
			switch {
			case errors.As(err, &ne) && ne.Timeout() || errors.Is(err, os.ErrDeadlineExceeded):
				_ = sh.conn.SetReadDeadline(time.Time{})
				continue
			case udpsock.IsICMPReport(err):
				sh.report(err)
				continue
			case udpsock.IsTruncated(err):
				continue
			}
			if !errors.Is(err, net.ErrClosed) {
				sh.readErr = err
				close(sh.dead)
				sh.retire(true)
			}
			return
		}
		sh.route(b, n, from)
	}
}

// addrPortReader and addrPortWriter are *net.UDPConn's allocation-free
// read and write, which a conn may have.
type (
	addrPortReader interface {
		ReadFromUDPAddrPort([]byte) (int, netip.AddrPort, error)
	}
	addrPortWriter interface {
		WriteToUDPAddrPort([]byte, netip.AddrPort) (int, error)
	}
)

func (sh *portShare) read(buf []byte) (int, netip.AddrPort, error) {
	if r, ok := sh.conn.(addrPortReader); ok {
		n, from, err := r.ReadFromUDPAddrPort(buf)
		return n, netaddr.Canon(from), err
	}
	n, a, err := sh.conn.ReadFrom(buf)
	from, _ := netaddr.FromNetAddr(a)
	return n, from, err
}

// route gives the datagram in b to its member or members:
//
//  1. among the members still punching, the only one when no member
//     claimed the source, else the one whose classifier accepts it (a
//     claimed source only when a punching member wrote to it) — the
//     session key opens it;
//  2. else the member that claimed the source at the handover;
//  3. else every member still punching that wrote to the source.
//
// Anything else is dropped. Only datagrams in holepunch's forms are
// classified (an upper-layer packet never is), within a pre-AEAD rate
// limit, so a claimed path costs its datagrams no decryption.
func (sh *portShare) route(b *[readBufferSize]byte, n int, from netip.AddrPort) {
	pkt := b[:n]
	var owner *sharedConn
	sh.mu.Lock()
	targets, open := sh.scratch[:0], sh.open[:0]
	for _, c := range sh.members {
		if c.claims == nil {
			open = append(open, c)
		} else if _, ok := c.claims[from]; ok {
			owner = c
		}
	}
	sh.mu.Unlock()
	switch {
	case len(open) == 1 && owner == nil:
		targets = append(targets, open[0])
	case len(open) > 0 && (owner == nil || sh.wroteBy(open, from)) && holepunchForm(pkt) && sh.classify.take(time.Now(), 0):
		for _, c := range open {
			if c.accept != nil && c.accept(pkt) {
				targets = append(targets, c)
				break
			}
		}
	}
	if len(targets) == 0 && owner != nil {
		targets = append(targets, owner)
	}
	if len(targets) == 0 && len(open) > 0 {
		sh.mu.Lock()
		for _, c := range open {
			if _, ok := c.wrote[from]; ok {
				targets = append(targets, c)
			}
		}
		sh.mu.Unlock()
	}
	sh.scratch, sh.open = targets, open
	defer clear(sh.open)
	defer clear(sh.scratch)
	if len(targets) == 0 {
		sh.bufs.Put(b)
		return
	}
	for _, c := range targets[1:] {
		cb, _ := sh.bufs.Get().(*[readBufferSize]byte)
		copy(cb[:n], pkt)
		c.deliver(shareItem{buf: cb, n: n, from: from})
	}
	targets[0].deliver(shareItem{buf: b, n: n, from: from})
}

// wroteBy reports whether a member of open wrote to from: a claimed source
// is classified only then, so a Session's own traffic costs no decryption
// and no classification budget.
func (sh *portShare) wroteBy(open []*sharedConn, from netip.AddrPort) bool {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	for _, c := range open {
		if _, ok := c.wrote[from]; ok {
			return true
		}
	}
	return false
}

// holepunchForm reports whether pkt may be a holepunch datagram: an opener
// or a sealed packet by its first byte and length.
func holepunchForm(pkt []byte) bool {
	if udpwire.Wrapped(pkt) {
		_, d := udpwire.Unwrap(pkt)
		return d == udpwire.OK
	}
	return udpwire.Precheck(pkt, udpwire.MinPeerPacket) == udpwire.OK
}

// report hands an ICMP report on when it can only concern one session: to
// the only member still punching. It names no address, so with several it
// is dropped rather than counted against sessions it does not concern; a
// Session's member never gets it.
func (sh *portShare) report(err error) {
	var to *sharedConn
	sh.mu.Lock()
	for _, c := range sh.members {
		if c.claims != nil {
			continue
		}
		if to != nil {
			sh.mu.Unlock()
			return
		}
		to = c
	}
	sh.mu.Unlock()
	if to != nil {
		to.deliver(shareItem{err: err})
	}
}

// acquire takes the write turn for c; it fails when c closes or its write
// deadline passes first.
func (sh *portShare) acquire(c *sharedConn) error {
	select {
	case sh.turn <- struct{}{}:
		return nil
	default:
	}
	var expire <-chan time.Time
	if d := c.writeDeadline(); !d.IsZero() {
		wait := time.Until(d)
		if wait <= 0 {
			return os.ErrDeadlineExceeded
		}
		t := time.NewTimer(wait)
		defer t.Stop()
		expire = t.C
	}
	select {
	case sh.turn <- struct{}{}:
		return nil
	case <-c.closed:
		return net.ErrClosed
	case <-expire:
		return os.ErrDeadlineExceeded
	}
}

// write writes out to `to` with c's hop limit, under the write turn.
func (sh *portShare) write(c *sharedConn, out []byte, to netip.AddrPort) (int, error) {
	if err := sh.acquire(c); err != nil {
		return 0, err
	}
	defer func() { <-sh.turn }()
	if hops := int(c.hops.Load()); hops != sh.curHop {
		switch err := sh.hop.set(hops); {
		case err == nil:
			sh.curHop = hops
		case hops == 0 || sh.curHop == 0:
			// A packet must not leave with a TTL it did not ask for; a
			// low-TTL one at another low TTL is still what it meant.
			return 0, err
		}
	}
	if err := sh.conn.SetWriteDeadline(c.writeDeadline()); err != nil {
		return 0, err
	}
	if w, ok := sh.conn.(addrPortWriter); ok {
		return w.WriteToUDPAddrPort(out, to)
	}
	return sh.conn.WriteTo(out, netaddr.UDPAddr(to))
}

// setHop applies hops at once, under the write turn, so that an unsupported
// TTL shows as the error of SetHopLimit.
func (sh *portShare) setHop(c *sharedConn, hops int) error {
	if err := sh.acquire(c); err != nil {
		return err
	}
	defer func() { <-sh.turn }()
	if err := sh.hop.set(hops); err != nil {
		return err
	}
	sh.curHop = hops
	c.hops.Store(int32(hops))
	return nil
}

// shareItem is one queued datagram, or an error for the reader of a member.
type shareItem struct {
	buf  *[readBufferSize]byte
	err  error
	n    int
	from netip.AddrPort
}

// sharedConn is one session's member of a shared socket: a net.PacketConn
// whose reads are the datagrams the reader routed to it and whose writes go
// out on the shared socket with its own hop limit and write deadline.
type sharedConn struct {
	sh     *portShare
	accept func([]byte) bool // the session's classifier; read by the reader only
	q      chan shareItem
	closed chan struct{}
	rd     deadline

	// guarded by sh.mu
	claims map[netip.AddrPort]struct{} // set by claim: the handed-over remotes
	wrote  map[netip.AddrPort]struct{}

	wdMu sync.Mutex
	wd   time.Time

	closeOnce sync.Once
	hops      atomic.Int32
}

// deliver queues it, dropping it when the queue is full.
func (c *sharedConn) deliver(it shareItem) {
	select {
	case c.q <- it:
	default:
		if it.buf != nil {
			c.sh.bufs.Put(it.buf)
		}
	}
}

// claim makes c the only receiver of the datagrams from remotes, and of
// nothing else: the handover. It fails, claiming nothing, when another
// member holds one of them.
func (c *sharedConn) claim(remotes []netip.AddrPort) bool {
	m := make(map[netip.AddrPort]struct{}, len(remotes))
	for _, r := range remotes {
		m[netaddr.Canon(r)] = struct{}{}
	}
	sh := c.sh
	sh.mu.Lock()
	defer sh.mu.Unlock()
	for _, o := range sh.members {
		if o == c || o.claims == nil {
			continue
		}
		for r := range m {
			if _, ok := o.claims[r]; ok {
				return false
			}
		}
	}
	c.claims, c.wrote = m, nil
	return true
}

// ReadFromUDPAddrPort reads the next datagram routed to c.
func (c *sharedConn) ReadFromUDPAddrPort(p []byte) (int, netip.AddrPort, error) {
	if isClosed(c.closed) {
		return 0, netip.AddrPort{}, net.ErrClosed
	}
	if isClosed(c.rd.wait()) {
		return 0, netip.AddrPort{}, os.ErrDeadlineExceeded
	}
	select {
	case it := <-c.q:
		return c.take(p, it)
	case <-c.closed:
		return 0, netip.AddrPort{}, net.ErrClosed
	case <-c.rd.wait():
		return 0, netip.AddrPort{}, os.ErrDeadlineExceeded
	case <-c.sh.dead:
		select {
		case it := <-c.q:
			return c.take(p, it)
		default:
		}
		return 0, netip.AddrPort{}, c.sh.readErr
	}
}

func (c *sharedConn) take(p []byte, it shareItem) (int, netip.AddrPort, error) {
	if it.err != nil {
		return 0, netip.AddrPort{}, it.err
	}
	n := copy(p, it.buf[:it.n])
	c.sh.bufs.Put(it.buf)
	return n, it.from, nil
}

// ReadFrom implements net.PacketConn.
func (c *sharedConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, from, err := c.ReadFromUDPAddrPort(p)
	if err != nil {
		return 0, nil, err
	}
	return n, netaddr.UDPAddr(from), nil
}

// WriteToUDPAddrPort writes p to `to` on the shared socket.
func (c *sharedConn) WriteToUDPAddrPort(p []byte, to netip.AddrPort) (int, error) {
	if isClosed(c.closed) {
		return 0, net.ErrClosed
	}
	to = netaddr.Canon(to)
	n, err := c.sh.write(c, p, to)
	if err == nil {
		c.noteWrote(to)
	}
	return n, err
}

// WriteTo implements net.PacketConn.
func (c *sharedConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	to, ok := netaddr.FromNetAddr(addr)
	if !ok {
		return 0, &net.OpError{Op: "write", Net: c.sh.key.network, Addr: addr, Err: errors.New("invalid address")}
	}
	return c.WriteToUDPAddrPort(p, to)
}

// noteWrote remembers that c wrote to `to`, within shareMaxWrites, while it
// is punching: route rule 3.
func (c *sharedConn) noteWrote(to netip.AddrPort) {
	sh := c.sh
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if c.claims != nil || len(c.wrote) >= shareMaxWrites {
		return
	}
	if _, ok := c.wrote[to]; ok {
		return
	}
	if c.wrote == nil {
		c.wrote = map[netip.AddrPort]struct{}{}
	}
	c.wrote[to] = struct{}{}
}

// Close leaves the shared socket; the last member closes it.
func (c *sharedConn) Close() error {
	first := false
	c.closeOnce.Do(func() {
		first = true
		close(c.closed)
		c.rd.stop()
		c.sh.remove(c)
	drain:
		for {
			select {
			case it := <-c.q:
				if it.buf != nil {
					c.sh.bufs.Put(it.buf)
				}
			default:
				break drain
			}
		}
	})
	if !first {
		return net.ErrClosed
	}
	return nil
}

// LocalAddr returns the shared socket's local address.
func (c *sharedConn) LocalAddr() net.Addr { return c.sh.local }

// SetDeadline sets the read and write deadlines.
func (c *sharedConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

// SetReadDeadline sets c's own read deadline; a past one wakes a blocked
// read at once.
func (c *sharedConn) SetReadDeadline(t time.Time) error {
	if isClosed(c.closed) {
		return net.ErrClosed
	}
	c.rd.set(t)
	return nil
}

// SetWriteDeadline sets c's own write deadline, applied to the shared
// socket for each of c's writes.
func (c *sharedConn) SetWriteDeadline(t time.Time) error {
	if isClosed(c.closed) {
		return net.ErrClosed
	}
	c.wdMu.Lock()
	c.wd = t
	c.wdMu.Unlock()
	return nil
}

func (c *sharedConn) writeDeadline() time.Time {
	c.wdMu.Lock()
	defer c.wdMu.Unlock()
	return c.wd
}

// SetHopLimit implements HopLimiter: c's writes leave with hops (0: the
// socket's default).
func (c *sharedConn) SetHopLimit(hops int) error {
	if isClosed(c.closed) {
		return net.ErrClosed
	}
	return c.sh.setHop(c, hops)
}

// codecAccepts returns the classifier of one member: the datagram, or the
// packet inside its opener, opens with the session key. Its scratch keeps
// the datagram intact; only that member's shared reader calls it, so each
// member gets its own. A nil codec accepts nothing.
func codecAccepts(codec *udpwire.Codec) func([]byte) bool {
	if codec == nil {
		return nil
	}
	scratch := make([]byte, udpwire.MaxPlaintext)
	return func(pkt []byte) bool {
		if udpwire.Wrapped(pkt) {
			inner, d := udpwire.Unwrap(pkt)
			if d != udpwire.OK {
				return false
			}
			pkt = inner
		}
		return codec.Open(pkt, scratch, nil, nil) == udpwire.OK
	}
}

// deadline is a resettable read deadline in the style of net.Pipe: a
// channel closed once the deadline has passed. Moving the deadline keeps
// the channel while it is open, so blocked reads see the new time without
// being woken.
type deadline struct {
	timer   *time.Timer
	cancel  chan struct{}
	mu      sync.Mutex
	stopped bool
}

func newDeadline() deadline { return deadline{cancel: make(chan struct{})} }

func isClosed(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

// set moves the deadline to t; the zero t removes it.
func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stopped {
		return
	}
	if d.timer != nil && !d.timer.Stop() {
		<-d.cancel // the timer fired: wait for its close
	}
	d.timer = nil
	closed := isClosed(d.cancel)
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}
		return
	}
	if dur := time.Until(t); dur > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		cancel := d.cancel
		d.timer = time.AfterFunc(dur, func() { close(cancel) })
		return
	}
	if !closed {
		close(d.cancel)
	}
}

func (d *deadline) wait() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cancel
}

func (d *deadline) stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stopped = true
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
}
