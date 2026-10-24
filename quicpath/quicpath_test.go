package quicpath_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/quicpath"
)

// TestPipe: pinned peers connect on the primary path and carry a stream;
// Close is idempotent, closes the session's sockets, and the peer sees its
// pipe closed by the peer.
func TestPipe(t *testing.T) {
	p := newPinned(t)
	dial, acc := p.connect(t, p.ids, nil)
	if dial.err != nil || acc.err != nil {
		t.Fatalf("dial %v, accept %v", dial.err, acc.err)
	}
	if dial.conn.Path().RemoteAddr != p.sess[0].Result().Path.RemoteAddr || acc.conn.Path().RemoteAddr != p.sess[1].Result().Path.RemoteAddr {
		t.Fatalf("paths %v / %v", dial.conn.Path(), acc.conn.Path())
	}
	if dial.conn.Err() != nil || acc.conn.Err() != nil {
		t.Fatalf("new pipe dead: %v / %v", dial.conn.Err(), acc.conn.Err())
	}
	served := make(chan error, 1)
	go func() { served <- echo(acc.conn) }()
	roundTrip(t, dial.conn, "over the punched path")
	if err := <-served; err != nil {
		t.Fatal(err)
	}

	first := dial.conn.Close()
	if again := dial.conn.Close(); !errors.Is(again, first) {
		t.Fatalf("second Close %v, first %v", again, first)
	}
	if err := dial.conn.Err(); !errors.Is(err, quicpath.ErrClosed) {
		t.Fatalf("closed pipe: %v", err)
	}
	if n := p.hosts[0].OpenSockets(); n != 0 {
		t.Fatalf("%d initiator sockets open after Close", n)
	}
	if err := waitDone(t, acc.conn, 5*time.Second); !errors.Is(err, quicpath.ErrPeerClosed) {
		t.Fatalf("peer's pipe: %v", err)
	}
	_ = acc.conn.Close()
	if n := p.hosts[1].OpenSockets(); n != 0 {
		t.Fatalf("%d responder sockets open after Close", n)
	}
}

// TestPinMismatch: each side refuses a peer whose certificate is not the
// one it announced; neither side gets a pipe, and the sessions stay the
// callers'.
func TestPinMismatch(t *testing.T) {
	for name, impostor := range map[string]int{"initiator": 0, "responder": 1} {
		t.Run(name, func(t *testing.T) {
			p := newPinned(t)
			ids := p.ids
			ids[impostor] = identity(t)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			done := make(chan connected, 1)
			go func() {
				c, err := quicpath.Accept(ctx, p.sess[1], p.tlsConfig(t, 1, ids[1]), nil)
				done <- connected{c, err}
			}()
			start := time.Now()
			c, err := quicpath.Dial(ctx, p.sess[0], p.tlsConfig(t, 0, ids[0]), nil)
			failed := p.sess[:]
			if err == nil {
				failed = p.sess[1:] // the impostor's Conn owned its session
				// A TLS 1.3 client finishes its side of the handshake before
				// the server checks its certificate: the impostor initiator
				// may get a connection, which the responder then closes.
				if impostor != 0 {
					t.Fatal("dialed an impostor responder")
				}
				if err := waitDone(t, c, 2*time.Second); err == nil {
					t.Fatal("impostor's pipe alive")
				}
				_ = c.Close()
			} else if impostor == 1 && time.Since(start) > time.Second {
				t.Fatalf("dial to an impostor took %v: %v", time.Since(start), err)
			}
			if a := <-done; a.err == nil {
				_ = a.conn.Close()
				t.Fatal("responder accepted")
			}
			// The failures left the sessions open.
			for i, s := range failed {
				if _, err := s.PacketConn().WriteTo([]byte("x"), net.UDPAddrFromAddrPort(s.Result().Path.RemoteAddr)); err != nil {
					t.Fatalf("side %d socket after failure: %v", i, err)
				}
			}
		})
	}
}

// TestIdleTimeout: a peer that vanishes without closing — its socket
// closed under QUIC — leaves the pipe to die of the idle timeout, which the
// caller's quic.Config shortens; the peer's own pipe died of its closed
// socket.
func TestIdleTimeout(t *testing.T) {
	p := newPinned(t)
	conf := &quic.Config{MaxIdleTimeout: 400 * time.Millisecond, KeepAlivePeriod: 100 * time.Millisecond}
	dial, acc := p.connect(t, p.ids, conf)
	if dial.err != nil || acc.err != nil {
		t.Fatalf("dial %v, accept %v", dial.err, acc.err)
	}
	// Keep-alives hold the idle pipe open meanwhile.
	time.Sleep(time.Second)
	if dial.conn.Err() != nil || acc.conn.Err() != nil {
		t.Fatalf("idle pipe died: %v / %v", dial.conn.Err(), acc.conn.Err())
	}
	_ = p.sess[1].Close()
	if err := waitDone(t, dial.conn, 3*time.Second); !errors.Is(err, quicpath.ErrIdleTimeout) {
		t.Fatalf("pipe to a vanished peer: %v", err)
	}
	if err := waitDone(t, acc.conn, time.Second); !errors.Is(err, quicpath.ErrClosed) {
		t.Fatalf("pipe on a closed socket: %v", err)
	}
}

// TestRoles: the initiator dials and the responder accepts; neither does
// the other's part, and a TLS configuration without an application
// protocol is refused. The sessions stay open.
func TestRoles(t *testing.T) {
	p := newPinned(t)
	ctx := context.Background()
	if _, err := quicpath.Accept(ctx, p.sess[0], p.tlsConfig(t, 0, p.ids[0]), nil); !errors.Is(err, quicpath.ErrRole) {
		t.Fatalf("initiator Accept: %v", err)
	}
	if _, err := quicpath.Dial(ctx, p.sess[1], p.tlsConfig(t, 1, p.ids[1]), nil); !errors.Is(err, quicpath.ErrRole) {
		t.Fatalf("responder Dial: %v", err)
	}
	conf := p.tlsConfig(t, 0, p.ids[0])
	conf.NextProtos = nil
	if _, err := quicpath.Dial(ctx, p.sess[0], conf, nil); err == nil {
		t.Fatal("Dial without NextProtos")
	}
	e, err := quicpath.NewEndpoint(p.sess[0], p.tlsConfig(t, 0, p.ids[0]), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Dial(ctx, len(e.Paths())); err == nil {
		t.Fatal("Dial on a path out of range")
	}
	// A closed Endpoint dials nothing.
	_ = e.Close()
	if _, err := e.Dial(ctx, 0); !errors.Is(err, quicpath.ErrClosed) {
		t.Fatalf("Dial after Close: %v", err)
	}
	if n := p.hosts[0].OpenSockets(); n != 0 {
		t.Fatalf("%d sockets open after Endpoint.Close", n)
	}
}

// TestDialStopsWhenSocketClosed: closing the session under a dial ends it
// at once, without further attempts.
func TestDialStopsWhenSocketClosed(t *testing.T) {
	p := newPinned(t) // the responder never accepts
	timer := time.AfterFunc(200*time.Millisecond, func() { _ = p.sess[0].Close() })
	defer timer.Stop()
	start := time.Now()
	_, err := quicpath.Dial(context.Background(), p.sess[0], p.tlsConfig(t, 0, p.ids[0]), nil)
	if !errors.Is(err, quicpath.ErrClosed) || time.Since(start) > 2*time.Second {
		t.Fatalf("Dial: %v after %v", err, time.Since(start))
	}
}

// TestAcceptBounded: an initiator that never dials leaves the responder
// waiting the session's TransportTimeout at most.
func TestAcceptBounded(t *testing.T) {
	p := newPinned(t)
	limit := p.sess[1].Result().TransportTimeout
	start := time.Now()
	_, err := quicpath.Accept(context.Background(), p.sess[1], p.tlsConfig(t, 1, p.ids[1]), nil)
	if d := time.Since(start); !errors.Is(err, context.DeadlineExceeded) || d < limit-100*time.Millisecond || d > limit+time.Second {
		t.Fatalf("Accept: %v after %v (TransportTimeout %v)", err, d, limit)
	}
}

// TestMultiPath: an Endpoint runs one pipe per confirmed path — a LAN and
// a public path through one hairpinning NAT, which may share a socket —
// whatever order the two sides take them in; a pipe that died is replaced
// on its path; and Close ends every pipe.
func TestMultiPath(t *testing.T) {
	w := newWorld(t)
	cfg := nattest.PortRestricted()
	cfg.Hairpin = true
	nat := w.n.NAT(cfg)
	ids := [2]*quicpath.Identity{identity(t), identity(t)}
	hosts := [2]*nattest.Host{nat.Host(), nat.Host()}
	sess := w.punch(t, [2]side{{hosts[0], ids[0].TransportData()}, {hosts[1], ids[1].TransportData()}}, 2)
	var eps [2]*quicpath.Endpoint
	for i, s := range sess {
		conf, err := ids[i].TLSConfig(s.Result())
		if err != nil {
			t.Fatal(err)
		}
		if eps[i], err = quicpath.NewEndpoint(s, conf, nil); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = eps[i].Close() })
	}
	paths := eps[0].Paths()
	if len(paths) != 2 {
		t.Fatalf("%d paths, want 2: %+v", len(paths), paths)
	}
	t.Logf("paths %s/%s, %d socket(s)", paths[0].Kind, paths[1].Kind, len(sess[0].PacketConns()))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// The responder accepts the paths in the reverse order of the dials:
	// a pipe arriving for the other path waits for its Accept.
	accepted := make(chan [2]connected, 1)
	go func() {
		var out [2]connected
		for _, i := range []int{1, 0} {
			c, err := eps[1].Accept(ctx, i)
			out[i] = connected{c, err}
		}
		accepted <- out
	}()
	var dials [2]*quicpath.Conn
	for i := range 2 {
		c, err := eps[0].Dial(ctx, i)
		if err != nil {
			t.Fatalf("dial path %d: %v", i, err)
		}
		dials[i] = c
	}
	accs := <-accepted
	for i := range 2 {
		if accs[i].err != nil {
			t.Fatalf("accept path %d: %v", i, accs[i].err)
		}
		if got := accs[i].conn.Path(); got.Kind != paths[i].Kind {
			t.Fatalf("path %d: accepted on %s, dialed on %s", i, got.Kind, paths[i].Kind)
		}
	}
	for i := range 2 {
		served := make(chan error, 1)
		go func() { served <- echo(accs[i].conn) }()
		roundTrip(t, dials[i], "path "+string(paths[i].Kind))
		if err := <-served; err != nil {
			t.Fatal(err)
		}
	}

	// The extra path's pipe dies and is replaced; the primary one stays.
	_ = dials[1].Close()
	if err := waitDone(t, accs[1].conn, 5*time.Second); !errors.Is(err, quicpath.ErrPeerClosed) {
		t.Fatalf("closed pipe: %v", err)
	}
	_ = accs[1].conn.Close()
	again := make(chan connected, 1)
	go func() {
		c, err := eps[1].Accept(ctx, 1)
		again <- connected{c, err}
	}()
	redial, err := eps[0].Dial(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	re := <-again
	if re.err != nil {
		t.Fatal(re.err)
	}
	served := make(chan error, 1)
	go func() { served <- echo(re.conn) }()
	roundTrip(t, redial, "again")
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	if dials[0].Err() != nil {
		t.Fatalf("primary pipe died: %v", dials[0].Err())
	}

	// Close ends every pipe on both ends.
	if err := eps[0].Close(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*quicpath.Conn{dials[0], redial} {
		if err := c.Err(); !errors.Is(err, quicpath.ErrClosed) {
			t.Fatalf("pipe after Endpoint.Close: %v", err)
		}
	}
	for _, c := range []*quicpath.Conn{accs[0].conn, re.conn} {
		if err := waitDone(t, c, 5*time.Second); !errors.Is(err, quicpath.ErrPeerClosed) {
			t.Fatalf("peer's pipe after Endpoint.Close: %v", err)
		}
	}
	if n := hosts[0].OpenSockets(); n != 0 {
		t.Fatalf("%d sockets open after Endpoint.Close", n)
	}
}
