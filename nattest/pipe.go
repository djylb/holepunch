package nattest

import (
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"
)

// defaultPipeBuffer is the per-direction buffer of a pipe.
const defaultPipeBuffer = 256 << 10

// PipeConfig configures a control link created by [Network.Pipe].
type PipeConfig struct {
	// DelayAB and DelayBA are the one-way delays; they may differ, for RTT
	// alignment tests.
	DelayAB, DelayBA time.Duration
	// Jitter adds a uniform offset in [-Jitter, +Jitter] per write; the byte
	// order is always preserved.
	Jitter time.Duration
	// BufferBytes bounds the bytes written but not yet read, per direction;
	// a full buffer blocks Write like TCP back-pressure. The default is
	// 256 KiB.
	BufferBytes int

	// A and B optionally own the two ends: Host.Crash closes them, and each
	// end reports its host's public address, the outermost NAT's external
	// IPv4 for a host behind NATs, as a TCP server would see it. Without a
	// host an end reports a loopback address.
	A, B *Host
}

// pipe is the state shared by the two ends of a control link; mu guards
// everything, including the ends' closed flags.
type pipe struct {
	n        *Network
	mu       sync.Mutex
	ab, ba   *pipeDir
	bufBytes int
	jitter   time.Duration
	rng      *rand.Rand
	cut      bool
	hole     bool
	cutCh    chan struct{} // closed by Cut
	ends     [2]*PipeConn
}

// pipeDir is one direction of a pipe.
type pipeDir struct {
	delay        time.Duration
	lastAt       time.Duration // arrival time of the last chunk, to keep order under jitter
	ready        []byte        // arrived, not yet read
	pending      int           // written, not yet arrived
	fin          bool          // the writer's Close has arrived
	readerClosed bool
	readable     chan struct{} // signalled when ready grows or fin arrives
	writable     chan struct{} // signalled when buffer space frees up
}

// pipeChunk is data (or the FIN of a Close) in flight on a pipe.
type pipeChunk struct {
	pipe *pipe
	dir  *pipeDir
	data []byte
	fin  bool
}

func signal(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

// PipeConn is one end of an in-order stream control link that does not
// traverse any NAT, standing in for the TCP connection between a client and
// the coordinator. It implements net.Conn; deadlines follow the network's
// clock. All methods are safe for concurrent use.
type PipeConn struct {
	p            *pipe
	tx, rx       *pipeDir
	host         *Host
	laddr, raddr net.Addr
	closed       bool // guarded by p.mu
	closedCh     chan struct{}
	rd, wd       deadline
}

// Pipe creates a bidirectional, in-order byte stream between two ends, for
// example the control connections of the clients and the coordinator.
func (n *Network) Pipe(cfg PipeConfig) (a, b *PipeConn) {
	if cfg.BufferBytes <= 0 {
		cfg.BufferBytes = defaultPipeBuffer
	}
	newDir := func(delay time.Duration) *pipeDir {
		return &pipeDir{delay: delay, readable: make(chan struct{}, 1), writable: make(chan struct{}, 1)}
	}
	n.topo.Lock()
	idx := len(n.pipes) + 1
	p := &pipe{
		n: n, bufBytes: cfg.BufferBytes, jitter: cfg.Jitter,
		rng:   n.rng("pipe", idx),
		ab:    newDir(cfg.DelayAB),
		ba:    newDir(cfg.DelayBA),
		cutCh: make(chan struct{}),
	}
	addrA, addrB := pipeAddr(cfg.A, 2*idx), pipeAddr(cfg.B, 2*idx+1)
	a = &PipeConn{p: p, tx: p.ab, rx: p.ba, host: cfg.A, laddr: addrA, raddr: addrB, closedCh: make(chan struct{}), rd: newDeadline(), wd: newDeadline()}
	b = &PipeConn{p: p, tx: p.ba, rx: p.ab, host: cfg.B, laddr: addrB, raddr: addrA, closedCh: make(chan struct{}), rd: newDeadline(), wd: newDeadline()}
	p.ends = [2]*PipeConn{a, b}
	closed := n.closed.Load()
	if !closed {
		n.pipes = append(n.pipes, p)
	}
	n.topo.Unlock()
	if closed {
		p.shutdown()
		return a, b
	}
	for _, c := range p.ends {
		if c.host != nil {
			c.host.mu.Lock()
			c.host.pipes[c] = struct{}{}
			c.host.mu.Unlock()
		}
	}
	return a, b
}

// pipeAddr is the TCP address of the k-th pipe end on h.
func pipeAddr(h *Host, k int) net.Addr {
	port := uint16(40000 + k%20000)
	if h == nil {
		return net.TCPAddrFromAddrPort(netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), port))
	}
	return net.TCPAddrFromAddrPort(netip.AddrPortFrom(h.publicAddr(), port))
}

// publicAddr is the address a server on the core sees for h: its first
// address translated by every NAT on the way up.
func (h *Host) publicAddr() netip.Addr {
	if len(h.addrs) == 0 {
		return netip.IPv4Unspecified()
	}
	a := h.addrs[0]
	for nat := h.nat; nat != nil; nat = nat.parentNAT {
		f := nat.fam(a.Is6())
		if f == nil {
			break
		}
		switch f.mode {
		case modeTranslate:
			nat.mu.Lock()
			if len(f.ext) > 0 {
				a = f.ext[0]
			}
			nat.mu.Unlock()
		case modeNPT:
			a = f.nptOut(a)
		case modeIdentity: // the address passes unchanged
		}
	}
	return a
}

// arrival returns when data written now on d becomes readable; p.mu is held.
// Later writes never arrive before earlier ones.
func (p *pipe) arrival(d *pipeDir) time.Duration {
	at := p.n.now() + d.delay
	if p.jitter > 0 {
		at += time.Duration(p.rng.Int64N(int64(2*p.jitter)+1)) - p.jitter
	}
	at = max(at, d.lastAt)
	d.lastAt = at
	return at
}

// emit delivers c at once when it is already due and returns nil; otherwise
// it returns c for the caller to queue after unlocking. p.mu is held.
func (p *pipe) emit(c *pipeChunk, at time.Duration) *pipeChunk {
	if at <= p.n.now() {
		p.deliverLocked(c)
		return nil
	}
	return c
}

// queue hands c to the scheduler; when the network is closed the chunk is
// discarded and its buffer space returned.
func (p *pipe) queue(c *pipeChunk, at time.Duration) {
	if c == nil || p.n.sched.push(event{at: at, pc: c}) {
		return
	}
	p.mu.Lock()
	if !c.fin {
		c.dir.pending -= len(c.data)
		signal(c.dir.writable)
	}
	p.mu.Unlock()
}

func (p *pipe) deliver(c *pipeChunk) {
	p.mu.Lock()
	p.deliverLocked(c)
	p.mu.Unlock()
}

func (p *pipe) deliverLocked(c *pipeChunk) {
	d := c.dir
	if c.fin {
		if !p.cut && !p.hole {
			d.fin = true
			signal(d.readable)
		}
		return
	}
	d.pending -= len(c.data)
	if p.cut || p.hole || d.readerClosed {
		signal(d.writable)
		return
	}
	d.ready = append(d.ready, c.data...)
	signal(d.readable)
}

// Read reads delivered bytes, blocking until some have arrived; a
// zero-length Read returns at once. It returns io.EOF after Cut, and after
// the peer's Close once the data sent before it has been read.
func (c *PipeConn) Read(b []byte) (int, error) {
	p := c.p
	for {
		p.mu.Lock()
		switch {
		case c.closed:
			p.mu.Unlock()
			return 0, c.opErr("read", net.ErrClosed)
		case p.cut:
			p.mu.Unlock()
			return 0, io.EOF
		}
		rd := c.rd.wait()
		if isClosed(rd) {
			p.mu.Unlock()
			return 0, c.opErr("read", os.ErrDeadlineExceeded)
		}
		if len(b) == 0 {
			p.mu.Unlock()
			return 0, nil
		}
		if len(c.rx.ready) > 0 {
			n := copy(b, c.rx.ready)
			c.rx.ready = c.rx.ready[n:]
			if len(c.rx.ready) == 0 {
				c.rx.ready = nil
			}
			signal(c.rx.writable)
			p.mu.Unlock()
			return n, nil
		}
		if c.rx.fin {
			p.mu.Unlock()
			return 0, io.EOF
		}
		readable := c.rx.readable
		p.mu.Unlock()
		select {
		case <-readable:
		case <-rd:
		case <-p.cutCh:
		case <-c.closedCh:
		}
	}
}

// Write queues b for delivery after the one-way delay, blocking while the
// direction's buffer is full. It fails with ECONNRESET after Cut and with
// EPIPE once the peer has closed; on a blackholed pipe it succeeds and the
// data is lost.
func (c *PipeConn) Write(b []byte) (int, error) {
	p := c.p
	written := 0
	for {
		p.mu.Lock()
		switch {
		case c.closed:
			p.mu.Unlock()
			return written, c.opErr("write", net.ErrClosed)
		case p.cut:
			p.mu.Unlock()
			return written, c.opErr("write", syscall.ECONNRESET)
		case c.tx.readerClosed:
			p.mu.Unlock()
			return written, c.opErr("write", syscall.EPIPE)
		}
		wd := c.wd.wait()
		if isClosed(wd) {
			p.mu.Unlock()
			return written, c.opErr("write", os.ErrDeadlineExceeded)
		}
		if p.hole {
			p.mu.Unlock()
			return written + len(b), nil
		}
		if len(b) == 0 {
			p.mu.Unlock()
			return written, nil
		}
		if space := p.bufBytes - c.tx.pending - len(c.tx.ready); space > 0 {
			k := min(space, len(b))
			ch := &pipeChunk{pipe: p, dir: c.tx, data: append([]byte(nil), b[:k]...)}
			c.tx.pending += k
			at := p.arrival(c.tx)
			later := p.emit(ch, at)
			p.mu.Unlock()
			p.queue(later, at)
			b = b[k:]
			written += k
			continue
		}
		writable := c.tx.writable
		p.mu.Unlock()
		select {
		case <-writable:
		case <-wd:
		case <-p.cutCh:
		case <-c.closedCh:
		}
	}
}

// Close closes this end: its blocked reads and writes fail, the peer reads
// EOF once the data written before Close has arrived, and the peer's writes
// fail with EPIPE. A second Close returns an error wrapping net.ErrClosed.
func (c *PipeConn) Close() error {
	p := c.p
	p.mu.Lock()
	if c.closed {
		p.mu.Unlock()
		return c.opErr("close", net.ErrClosed)
	}
	c.closed = true
	close(c.closedCh)
	c.rx.readerClosed = true
	c.rx.ready = nil
	signal(c.rx.writable)
	var later *pipeChunk
	var at time.Duration
	if !p.cut && !p.hole {
		at = p.arrival(c.tx)
		later = p.emit(&pipeChunk{pipe: p, dir: c.tx, fin: true}, at)
	}
	p.mu.Unlock()
	p.queue(later, at)
	c.release()
	return nil
}

// release stops the end's deadline timers and detaches it from its host.
func (c *PipeConn) release() {
	c.rd.stop()
	c.wd.stop()
	if c.host != nil {
		c.host.mu.Lock()
		delete(c.host.pipes, c)
		c.host.mu.Unlock()
	}
}

// Cut breaks the link: reads on both ends return io.EOF and writes
// ECONNRESET at once, and the data in flight is lost.
func (c *PipeConn) Cut() {
	p := c.p
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cut {
		return
	}
	p.cut = true
	close(p.cutCh)
	p.ab.ready, p.ba.ready = nil, nil
}

// Blackhole silences the link in both directions, as a half-open connection
// does: writes succeed, nothing is delivered (neither data already in
// flight nor a later Close), and reads block once the delivered data is
// drained.
func (c *PipeConn) Blackhole() {
	p := c.p
	p.mu.Lock()
	p.hole = true
	p.mu.Unlock()
}

// SetDelay changes the one-way delay of both directions and the jitter for
// later writes.
func (c *PipeConn) SetDelay(oneWay, jitter time.Duration) {
	p := c.p
	p.mu.Lock()
	p.ab.delay, p.ba.delay = oneWay, oneWay
	p.jitter = jitter
	p.mu.Unlock()
}

// LocalAddr returns this end's address (see PipeConfig.A).
func (c *PipeConn) LocalAddr() net.Addr { return c.laddr }

// RemoteAddr returns the peer end's address.
func (c *PipeConn) RemoteAddr() net.Addr { return c.raddr }

// SetDeadline sets both deadlines.
func (c *PipeConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// SetReadDeadline implements net.Conn on the network's clock.
func (c *PipeConn) SetReadDeadline(t time.Time) error {
	if c.isClosed() {
		return c.opErr("set", net.ErrClosed)
	}
	c.rd.set(c.p.n, t)
	return nil
}

// SetWriteDeadline implements net.Conn on the network's clock.
func (c *PipeConn) SetWriteDeadline(t time.Time) error {
	if c.isClosed() {
		return c.opErr("set", net.ErrClosed)
	}
	c.wd.set(c.p.n, t)
	return nil
}

func (c *PipeConn) isClosed() bool {
	c.p.mu.Lock()
	defer c.p.mu.Unlock()
	return c.closed
}

func (c *PipeConn) opErr(op string, err error) error {
	return &net.OpError{Op: op, Net: "pipe", Source: c.laddr, Addr: c.raddr, Err: err}
}

// shutdown closes both ends without a FIN, when the network closes.
func (p *pipe) shutdown() {
	p.mu.Lock()
	var ends []*PipeConn
	for _, c := range p.ends {
		if !c.closed {
			c.closed = true
			close(c.closedCh)
			ends = append(ends, c)
		}
	}
	p.ab.ready, p.ba.ready = nil, nil
	p.mu.Unlock()
	for _, c := range ends {
		c.release()
	}
}
