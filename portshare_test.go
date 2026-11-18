package holepunch

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

const testPinnedPort = 41641

// shareHosts returns two public hosts of a fresh network.
func shareHosts(t *testing.T) (h, peer *nattest.Host) {
	t.Helper()
	n := nattest.NewNetwork()
	t.Cleanup(func() { _ = n.Close() })
	return n.PublicHost(netip.MustParseAddr("198.51.100.1")), n.PublicHost(netip.MustParseAddr("198.51.100.2"))
}

func joinT(t *testing.T, sp *SharedPorts, h *nattest.Host, accept func([]byte) bool) *sharedConn {
	t.Helper()
	c, err := sp.join(context.Background(), h, "udp4", netip.AddrPortFrom(netip.Addr{}, testPinnedPort), accept)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func readT(t *testing.T, c net.PacketConn) (string, netip.AddrPort) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	buf := make([]byte, readBufferSize)
	n, a, err := c.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	ap, _ := netip.ParseAddrPort(a.String())
	return string(trimHP(buf[:n])), ap
}

func noRead(t *testing.T, c net.PacketConn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	if n, a, err := c.ReadFrom(make([]byte, readBufferSize)); err == nil {
		t.Fatalf("unexpected datagram of %d bytes from %v", n, a)
	}
}

// hp is a datagram in holepunch's sealed form (first byte and length)
// carrying tag; trimHP returns the tag back, other datagrams unchanged.
func hp(tag string) []byte {
	b := make([]byte, udpwire.MinPeerPacket)
	b[0] = udpwire.B0Min
	copy(b[1:], tag)
	b[len(b)-1] = '#'
	return b
}

func trimHP(b []byte) []byte {
	if len(b) == udpwire.MinPeerPacket && b[0] == udpwire.B0Min && b[len(b)-1] == '#' {
		return bytes.TrimRight(b[1:len(b)-1], "\x00")
	}
	return b
}

// tagged classifies the hp datagrams whose tag starts with p.
func tagged(p string) func([]byte) bool {
	return func(b []byte) bool { return strings.HasPrefix(string(trimHP(b)), p) && len(b) == udpwire.MinPeerPacket }
}

// TestSharedPortsOneBind: members share one bind; the last close releases
// the port, and a later join binds it again.
func TestSharedPortsOneBind(t *testing.T) {
	h, _ := shareHosts(t)
	var sp SharedPorts
	a := joinT(t, &sp, h, nil)
	b := joinT(t, &sp, h, nil)
	if got := h.Stats().SocketsOpened; got != 1 {
		t.Fatalf("sockets opened = %d, want 1", got)
	}
	if a.LocalAddr().String() != b.LocalAddr().String() {
		t.Fatalf("local addrs differ: %v %v", a.LocalAddr(), b.LocalAddr())
	}
	_ = a.Close()
	if got := h.Stats().SocketsClosed; got != 0 {
		t.Fatal("socket closed with a member left")
	}
	_ = b.Close()
	if got := h.Stats().SocketsClosed; got != 1 {
		t.Fatalf("sockets closed = %d, want 1", got)
	}
	c := joinT(t, &sp, h, nil)
	_ = c.Close()
	if got := h.Stats().SocketsOpened; got != 2 {
		t.Fatalf("sockets opened = %d, want 2", got)
	}
}

// TestSharedPortsRoute checks the routing rules: a sole member gets all;
// among several, the classifier picks a holepunch datagram, the writers of
// a source get the rest, and nobody gets what no rule gives; a claim is
// exclusive and takes its source's datagrams but those a punching member
// classifies.
func TestSharedPortsRoute(t *testing.T) {
	h, ph := shareHosts(t)
	peer, err := ph.ListenPacket(context.Background(), "udp4", netip.AddrPort{}, "peer")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	other, err := ph.ListenPacket(context.Background(), "udp4", netip.AddrPort{}, "other")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	var sp SharedPorts
	a := joinT(t, &sp, h, tagged("A"))
	defer func() { _ = a.Close() }()
	to := net.UDPAddrFromAddrPort(netip.AddrPortFrom(h.Addrs()[0], testPinnedPort))
	send := func(c net.PacketConn, b []byte) {
		t.Helper()
		if _, err := c.WriteTo(b, to); err != nil {
			t.Fatal(err)
		}
	}
	want := func(c net.PacketConn, tag string) {
		t.Helper()
		if got, _ := readT(t, c); got != tag {
			t.Fatalf("read %q, want %q", got, tag)
		}
	}
	send(peer, []byte("x-sole"))
	want(a, "x-sole")
	b := joinT(t, &sp, h, tagged("B"))
	defer func() { _ = b.Close() }()
	send(peer, hp("B1"))
	send(peer, hp("A1"))
	want(b, "B1")
	want(a, "A1")
	// Nobody classifies them and nobody wrote to the source: dropped.
	send(peer, []byte("z-none"))
	send(peer, hp("Z"))
	noRead(t, a)
	noRead(t, b)
	// b wrote to peer: b gets peer's datagrams nobody classifies.
	pp, _ := netip.ParseAddrPort(peer.LocalAddr().String())
	peerAP := netip.AddrPortFrom(ph.Addrs()[0], pp.Port())
	if _, err := b.WriteToUDPAddrPort([]byte("hello"), peerAP); err != nil {
		t.Fatal(err)
	}
	want(peer, "hello")
	send(peer, []byte("z-writer"))
	want(b, "z-writer")
	noRead(t, a)
	// a claims peer; b cannot. Peer's datagrams go to a but those b, still
	// punching, classifies.
	if !a.claim([]netip.AddrPort{peerAP}) {
		t.Fatal("claim refused")
	}
	if b.claim([]netip.AddrPort{peerAP}) {
		t.Fatal("second claim of the same remote accepted")
	}
	send(peer, hp("B2"))
	want(b, "B2")
	send(peer, []byte("q-claimed"))
	send(peer, hp("A2"))
	want(a, "q-claimed")
	want(a, "A2")
	noRead(t, b)
	// From another source, b is the only member punching.
	send(other, []byte("o-1"))
	want(b, "o-1")
	noRead(t, a)
}

// TestSharedConnDeadline: a past read deadline wakes a blocked read, and
// Close ends it with net.ErrClosed.
func TestSharedConnDeadline(t *testing.T) {
	h, _ := shareHosts(t)
	var sp SharedPorts
	a := joinT(t, &sp, h, nil)
	errc := make(chan error, 1)
	go func() {
		_, _, err := a.ReadFrom(make([]byte, 8))
		errc <- err
	}()
	time.AfterFunc(20*time.Millisecond, func() { _ = a.SetReadDeadline(aLongTimeAgo) })
	if err := <-errc; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read err = %v", err)
	}
	_ = a.SetReadDeadline(time.Time{})
	go func() {
		_, _, err := a.ReadFrom(make([]byte, 8))
		errc <- err
	}()
	time.AfterFunc(20*time.Millisecond, func() { _ = a.Close() })
	if err := <-errc; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read err = %v", err)
	}
}

// TestSharedPortsConcurrentJoin: members joining and leaving at once never
// bind twice at the same time, never fail and leave the port free.
func TestSharedPortsConcurrentJoin(t *testing.T) {
	h, _ := shareHosts(t)
	var sp SharedPorts
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for range 16 {
		wg.Go(func() {
			for range 8 {
				c, err := sp.join(context.Background(), h, "udp4", netip.AddrPortFrom(netip.Addr{}, testPinnedPort), nil)
				if err != nil {
					errs <- err
					return
				}
				_ = c.SetHopLimit(3)
				_, _ = c.WriteToUDPAddrPort([]byte("x"), netip.MustParseAddrPort("198.51.100.2:9"))
				_ = c.Close()
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	st := h.Stats()
	if st.SocketsOpened != st.SocketsClosed {
		t.Fatalf("opened %d closed %d", st.SocketsOpened, st.SocketsClosed)
	}
	if len(sp.ports) != 0 {
		t.Fatalf("registry keeps %d sockets", len(sp.ports))
	}
}

// TestPinnedPortPairs runs two sessions at once on one host, both pinned to
// one port through SharedPorts, against two peers: both succeed on the
// pinned port over one bound socket, and each Session reads only its peer.
// The other sockets of the host are not pinned.
func TestPinnedPortPairs(t *testing.T) {
	w := newWorld(t)
	shared := w.n.PublicHost() // dual stack: a shared socket per family

	var sp SharedPorts
	// A member that classifies nothing holds the socket throughout: both
	// sessions join it, and every datagram goes through the classifiers.
	hold := joinT(t, &sp, shared, nil)
	defer func() { _ = hold.Close() }()
	pin := func(i int, o *Options) {
		if i == 0 {
			o.LocalPort, o.SharedPorts = testPinnedPort, &sp
		}
	}
	var runs [2]*pairRun
	var wg sync.WaitGroup
	for k := range runs {
		wg.Go(func() {
			ps := &pairScript{w: w, timeouts: testTimeouts()}
			runs[k] = runPairHosts(t, w, [2]*nattest.Host{shared, w.n.PublicHost()}, ps, pin)
		})
	}
	wg.Wait()
	defer func() {
		for _, pr := range runs {
			pr.closeAll()
		}
	}()
	for k, pr := range runs {
		for i, r := range pr.res {
			if r.err != nil {
				t.Fatalf("pair %d client %d: %v (script: %v)", k, i, r.err, pr.scriptE)
			}
		}
		if p := pr.res[0].sess.Result().Path.LocalAddr.Port(); p != testPinnedPort {
			t.Fatalf("pair %d: local port %d, want %d", k, p, testPinnedPort)
		}
	}
	// Two probe sockets on the host: the shared one of each family (on a
	// public host the prober opens no second socket).
	if n := shared.Stats().SocketsByPurpose[PurposeProbe]; n != 2 {
		t.Fatalf("probe sockets opened: %d, want 2", n)
	}
	// Each pinned Session hears its own peer and never the other pair's:
	// the datagrams queued before the handover (late server answers,
	// residual handshake packets) come first and are skipped.
	var peers [2]netip.AddrPort
	for k, pr := range runs {
		peers[k] = pr.res[0].sess.Result().Path.RemoteAddr
	}
	for k, pr := range runs {
		msg := []byte{'m', byte('0' + k)}
		to := pr.res[1].sess.Result().Path.RemoteAddr
		if _, err := pr.res[1].sess.PacketConn().WriteTo(msg, net.UDPAddrFromAddrPort(to)); err != nil {
			t.Fatal(err)
		}
	}
	for k, pr := range runs {
		pc := pr.res[0].sess.PacketConn()
		for {
			got, from := readT(t, pc)
			if from == peers[1-k] {
				t.Fatalf("pair %d read the other pair's peer", k)
			}
			if from == peers[k] && got == string([]byte{'m', byte('0' + k)}) {
				break
			}
		}
	}
}

// TestPinnedPortBusy: a pinned port another socket holds fails the session
// with local_port_bind_failed and ErrLocalPortUnavailable.
func TestPinnedPortBusy(t *testing.T) {
	w := newWorld(t)
	h := w.host(nil)
	hold, err := h.ListenPacket(context.Background(), "udp4", netip.AddrPortFrom(netip.Addr{}, testPinnedPort), "holder")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hold.Close() }()
	for _, sp := range []*SharedPorts{nil, new(SharedPorts)} {
		ps := &pairScript{w: w, timeouts: testTimeouts()}
		pr := runPairHosts(t, w, [2]*nattest.Host{h, w.host(nil)}, ps, func(i int, o *Options) {
			if i == 0 {
				o.LocalPort, o.SharedPorts = testPinnedPort, sp
			}
		})
		pr.closeAll()
		var he *Error
		err := pr.res[0].err
		if !errors.As(err, &he) || he.Reason != protocol.ReasonLocalPortBindFailed || !errors.Is(err, ErrLocalPortUnavailable) || !errors.Is(err, syscall.EADDRINUSE) {
			t.Fatalf("shared=%v: err = %v", sp != nil, err)
		}
	}
}

// hookNet is a nattest host whose sockets close slowly or fail their reads
// on demand.
type hookNet struct {
	*nattest.Host
	closing  chan struct{} // closed by a socket's Close, which then waits for release
	release  chan struct{}
	readFail chan error // a read takes an error from here
}

func newHookNet(h *nattest.Host) *hookNet {
	return &hookNet{Host: h, closing: make(chan struct{}, 1), release: make(chan struct{}), readFail: make(chan error, 1)}
}

func (n *hookNet) ListenPacket(ctx context.Context, network string, laddr netip.AddrPort, purpose string) (net.PacketConn, error) {
	c, err := n.Host.ListenPacket(ctx, network, laddr, purpose)
	if err != nil {
		return nil, err
	}
	return &hookConn{PacketConn: c, n: n}, nil
}

type hookConn struct {
	net.PacketConn
	n *hookNet
}

func (c *hookConn) ReadFrom(p []byte) (int, net.Addr, error) {
	type res struct {
		a   net.Addr
		err error
		n   int
	}
	ch := make(chan res, 1)
	go func() {
		n, a, err := c.PacketConn.ReadFrom(p)
		ch <- res{a, err, n}
	}()
	select {
	case r := <-ch:
		return r.n, r.a, r.err
	case err := <-c.n.readFail:
		_ = c.SetReadDeadline(aLongTimeAgo)
		<-ch
		_ = c.SetReadDeadline(time.Time{})
		return 0, nil, err
	}
}

func (c *hookConn) Close() error {
	select {
	case c.n.closing <- struct{}{}:
		<-c.n.release
	default:
	}
	return c.PacketConn.Close()
}

// TestSharedPortsJoinWhileClosing: a session joining while the last member
// closes the socket waits for the close and binds the port anew, instead
// of failing on the socket still bound.
func TestSharedPortsJoinWhileClosing(t *testing.T) {
	h, _ := shareHosts(t)
	n := newHookNet(h)
	var sp SharedPorts
	laddr := netip.AddrPortFrom(netip.Addr{}, testPinnedPort)
	a, err := sp.join(context.Background(), n, "udp4", laddr, nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		_ = a.Close()
		close(done)
	}()
	<-n.closing // the socket is being closed, still bound
	joined := make(chan error, 1)
	go func() {
		b, err := sp.join(context.Background(), n, "udp4", laddr, nil)
		if err == nil {
			_ = b.Close()
		}
		joined <- err
	}()
	select {
	case err := <-joined:
		t.Fatalf("join returned during the close: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(n.release)
	<-done
	if err := <-joined; err != nil {
		t.Fatal(err)
	}
	if st := h.Stats(); st.SocketsOpened != 2 || st.SocketsClosed != 2 {
		t.Fatalf("opened %d closed %d", st.SocketsOpened, st.SocketsClosed)
	}
}

// TestSharedPortsReadError: a read error ends the members' reads and
// closes the socket, so the next session binds the port anew.
func TestSharedPortsReadError(t *testing.T) {
	h, _ := shareHosts(t)
	n := newHookNet(h)
	close(n.release)
	var sp SharedPorts
	laddr := netip.AddrPortFrom(netip.Addr{}, testPinnedPort)
	a, err := sp.join(context.Background(), n, "udp4", laddr, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	boom := errors.New("boom")
	n.readFail <- boom
	if _, _, err := a.ReadFrom(make([]byte, 8)); !errors.Is(err, boom) {
		t.Fatalf("read err = %v", err)
	}
	b, err := sp.join(context.Background(), n, "udp4", laddr, nil)
	if err != nil {
		t.Fatalf("join after the read error: %v", err)
	}
	_ = b.Close()
}

// TestSharedPortsCanceledJoin: a join with a canceled context leaves no
// socket behind.
func TestSharedPortsCanceledJoin(t *testing.T) {
	h, _ := shareHosts(t)
	var sp SharedPorts
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c, err := sp.join(ctx, h, "udp4", netip.AddrPortFrom(netip.Addr{}, testPinnedPort), nil)
	if err == nil {
		_ = c.Close()
	}
	if st := h.Stats(); st.SocketsOpened != st.SocketsClosed || len(sp.ports) != 0 {
		t.Fatalf("opened %d closed %d, registry %d", st.SocketsOpened, st.SocketsClosed, len(sp.ports))
	}
}

// TestSharedConnWriteDeadline: a write waiting for another member's write
// honours its deadline.
func TestSharedConnWriteDeadline(t *testing.T) {
	h, _ := shareHosts(t)
	var sp SharedPorts
	a := joinT(t, &sp, h, nil)
	defer func() { _ = a.Close() }()
	a.sh.turn <- struct{}{} // another member's write in progress
	_ = a.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err := a.WriteToUDPAddrPort([]byte("x"), netip.MustParseAddrPort("198.51.100.2:9")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write err = %v", err)
	}
	<-a.sh.turn
	_ = a.SetWriteDeadline(time.Time{})
	if _, err := a.WriteToUDPAddrPort([]byte("x"), netip.MustParseAddrPort("198.51.100.2:9")); err != nil {
		t.Fatal(err)
	}
}
