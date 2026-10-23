package quicforward_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/standalone/broker"
	"github.com/djylb/holepunch/standalone/client"
	"github.com/djylb/holepunch/standalone/internal/testkit"
	"github.com/djylb/holepunch/standalone/internal/testworld"
	"github.com/djylb/holepunch/standalone/proto"
	"github.com/djylb/holepunch/standalone/quicforward"
	"github.com/djylb/holepunch/standalone/server"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

// hostRun serves "office" through hostC with h; the test's cleanup stops
// it.
func hostRun(t *testing.T, w *testworld.World, hostC *client.Client, reg client.Registration, h client.Handler) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	reg.HostID = "office"
	go func() {
		defer close(done)
		_ = hostC.Serve(ctx, reg, h)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	testkit.WaitFor(t, "the host to register", func() bool { return len(w.Broker.Snapshot().Hosts) == 1 })
}

// TestAcceptBounded: a dialer that never dials QUIC leaves the host waiting
// at most the session's TransportTimeout; then the listener, the transport
// and the socket are closed, and the failure is reported.
func TestAcceptBounded(t *testing.T) {
	reports := make(chan server.TransportReport, 1)
	w := testworld.New(t, testworld.Options{Server: func(c *server.Config) {
		c.OnTransport = func(r server.TransportReport) { reports <- r }
	}})
	hostID, err := quicforward.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dialID, err := quicforward.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hostH := w.NATHost(nattest.FullCone())
	type outcome struct {
		err error
		d   time.Duration
	}
	served := make(chan outcome, 1)
	hostRun(t, w, w.Client(hostH, nil), client.Registration{TransportMode: quicforward.Mode, TransportData: hostID.TransportData()},
		func(ctx context.Context, s *client.Session) {
			start := time.Now()
			err := quicforward.ServeSession(ctx, s, hostID, quicforward.HostConfig{Targets: []string{"svc.test:80"}})
			served <- outcome{err, time.Since(start)}
		})
	dialC := w.Client(w.NATHost(nattest.FullCone()), nil)
	s, err := dialC.Open(context.Background(), client.OpenRequest{HostID: "office", TransportMode: quicforward.Mode, TransportData: dialID.TransportData()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	limit := s.Result().TransportTimeout
	select {
	case o := <-served:
		if o.err == nil || o.d < limit-100*time.Millisecond || o.d > limit+2*time.Second {
			t.Fatalf("ServeSession: %v after %v (TransportTimeout %v)", o.err, o.d, limit)
		}
	case <-time.After(limit + 3*time.Second):
		t.Fatal("ServeSession still waiting")
	}
	if n := hostH.OpenSockets(); n != 0 {
		t.Fatalf("%d host sockets open", n)
	}
	select {
	case r := <-reports:
		if r.OK || r.SessionID != s.ID() {
			t.Fatalf("report %+v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no failure report")
	}
}

// pair punches a quicforward-mode session whose host side only holds the
// session open until the test ends, and returns both sides.
func pair(t *testing.T, w *testworld.World, hostID, dialID *quicforward.Identity) (host, dial *client.Session) {
	t.Helper()
	sessions := make(chan *client.Session, 1)
	hostRun(t, w, w.Client(w.NATHost(nattest.FullCone()), nil), client.Registration{TransportMode: quicforward.Mode, TransportData: hostID.TransportData()},
		func(ctx context.Context, s *client.Session) {
			sessions <- s
			<-ctx.Done()
		})
	dialC := w.Client(w.NATHost(nattest.FullCone()), nil)
	d, err := dialC.Open(context.Background(), client.OpenRequest{HostID: "office", TransportMode: quicforward.Mode, TransportData: dialID.TransportData()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return <-sessions, d
}

func identities(t *testing.T) (*quicforward.Identity, *quicforward.Identity) {
	t.Helper()
	a, err := quicforward.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := quicforward.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return a, b
}

// TestDialStopsWhenSocketClosed: closing the session's socket ends a dial
// at once, without further attempts.
func TestDialStopsWhenSocketClosed(t *testing.T) {
	w := testworld.New(t, testworld.Options{})
	hostID, dialID := identities(t)
	_, d := pair(t, w, hostID, dialID) // the host never listens
	go func() {
		time.Sleep(200 * time.Millisecond)
		_ = d.Close()
	}()
	// Without the stop, the first attempt alone would wait the session's
	// TransportTimeout (3 s).
	start := time.Now()
	_, err := quicforward.Dial(context.Background(), d, dialID)
	if !errors.Is(err, net.ErrClosed) || time.Since(start) > 2*time.Second {
		t.Fatalf("Dial: %v after %v", err, time.Since(start))
	}
}

// TestPinMismatch: each side refuses a peer whose certificate is not the
// one its TransportData announced. A host impostor fails the dial at the
// first attempt; a dialer impostor finishes its side of the handshake
// (TLS 1.3 clients do before the server checks them) and then sees the
// connection closed, while the host never accepts it.
func TestPinMismatch(t *testing.T) {
	impostor := func(t *testing.T) *quicforward.Identity {
		id, err := quicforward.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	accept := func(h *client.Session, id *quicforward.Identity) chan error {
		accepted := make(chan error, 1)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			c, err := quicforward.Accept(ctx, h, id)
			if err == nil {
				_ = c.Close()
			}
			accepted <- err
		}()
		return accepted
	}
	t.Run("dialer", func(t *testing.T) {
		w := testworld.New(t, testworld.Options{})
		hostID, dialID := identities(t)
		h, d := pair(t, w, hostID, dialID)
		accepted := accept(h, hostID)
		conn, err := quicforward.Dial(context.Background(), d, impostor(t))
		if err == nil {
			select {
			case <-conn.QUIC().Context().Done():
			case <-time.After(2 * time.Second):
				t.Fatal("impostor's connection still open")
			}
			_ = conn.Close()
		}
		if err := <-accepted; err == nil {
			t.Fatal("host accepted the impostor")
		}
	})
	t.Run("host", func(t *testing.T) {
		w := testworld.New(t, testworld.Options{})
		hostID, dialID := identities(t)
		h, d := pair(t, w, hostID, dialID)
		accepted := accept(h, impostor(t))
		start := time.Now()
		if _, err := quicforward.Dial(context.Background(), d, dialID); err == nil || time.Since(start) > 2*time.Second {
			t.Fatalf("dial to an impostor: %v after %v", err, time.Since(start))
		}
		if err := <-accepted; err == nil {
			t.Fatal("impostor host accepted")
		}
	})
}

// TestWrongTransport: a session that is not a pinned QUIC session is
// refused before any packet is sent.
func TestWrongTransport(t *testing.T) {
	w := testworld.New(t, testworld.Options{})
	id, _ := identities(t)
	sessions := make(chan *client.Session, 1)
	hostRun(t, w, w.Client(w.NATHost(nattest.FullCone()), nil), client.Registration{TransportMode: "udp_echo"},
		func(ctx context.Context, s *client.Session) {
			sessions <- s
			<-ctx.Done()
		})
	dialC := w.Client(w.NATHost(nattest.FullCone()), nil)
	d, err := dialC.Open(context.Background(), client.OpenRequest{HostID: "office", TransportMode: "udp_echo"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	if _, err := quicforward.Dial(context.Background(), d, id); !errors.Is(err, quicforward.ErrTransport) {
		t.Fatalf("Dial: %v", err)
	}
	if _, err := quicforward.Accept(context.Background(), <-sessions, id); !errors.Is(err, quicforward.ErrTransport) {
		t.Fatalf("Accept: %v", err)
	}
}

// TestStreamPolicy: a stream reaches only a target the host lists and the
// session's AccessPolicy allows; the host's first target is the default.
func TestStreamPolicy(t *testing.T) {
	w := testworld.New(t, testworld.Options{Broker: func(c *broker.Config) {
		c.Authorize = func(broker.OpenRequest, broker.HostInfo) (proto.AccessPolicy, error) {
			return proto.AccessPolicy{Targets: []string{"b.test:2"}}, nil
		}
	}})
	targets := &echoTargets{}
	ctx, cancel := context.WithCancel(context.Background())
	hostC := w.Client(w.NATHost(nattest.FullCone()), nil)
	served := make(chan error, 1)
	go func() {
		served <- quicforward.Serve(ctx, hostC, client.Registration{HostID: "office"},
			quicforward.HostConfig{Targets: []string{"a.test:1", "B.test:2"}, Dial: targets.dial})
	}()
	defer func() {
		cancel()
		<-served
		targets.wg.Wait()
	}()
	testkit.WaitFor(t, "the host to register", func() bool { return len(w.Broker.Snapshot().Hosts) == 1 })
	id, _ := identities(t)
	dialC := w.Client(w.NATHost(nattest.FullCone()), nil)
	d, err := dialC.Open(context.Background(), client.OpenRequest{HostID: "office", TransportMode: quicforward.Mode, TransportData: id.TransportData()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	conn, err := quicforward.Dial(context.Background(), d, id)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if conn.QUIC() == nil {
		t.Fatal("no QUIC connection")
	}
	for _, target := range []string{"", "a.test:1", "c.test:3", "bad"} {
		if _, err := conn.OpenStream(context.Background(), target); !errors.Is(err, quicforward.ErrRefused) {
			t.Fatalf("target %q: %v", target, err)
		}
	}
	st, err := conn.OpenStream(context.Background(), "b.test:2")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	roundTrip(t, st, []byte("allowed"))
	if got := targets.addresses(); len(got) != 1 || got[0] != "b.test:2" {
		t.Fatalf("dialed %v", got)
	}
	// Half-close: the echo service ends when the stream's sending side
	// does, and the relay hands the end back.
	if err := st.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = st.SetReadDeadline(time.Now().Add(5 * time.Second))
	if rest, err := io.ReadAll(st); err != nil || len(rest) != 0 {
		t.Fatalf("after half-close: %q %v", rest, err)
	}
}

// TestTargetUnreachable: a target that cannot be dialed is reported to
// the dialer.
func TestTargetUnreachable(t *testing.T) {
	w := testworld.New(t, testworld.Options{})
	ctx, cancel := context.WithCancel(context.Background())
	hostC := w.Client(w.NATHost(nattest.FullCone()), nil)
	served := make(chan error, 1)
	go func() {
		served <- quicforward.Serve(ctx, hostC, client.Registration{HostID: "office"}, quicforward.HostConfig{
			Targets: []string{"a.test:1"},
			Dial: func(context.Context, string) (net.Conn, error) {
				return nil, errors.New("connection refused")
			},
		})
	}()
	defer func() {
		cancel()
		<-served
	}()
	testkit.WaitFor(t, "the host to register", func() bool { return len(w.Broker.Snapshot().Hosts) == 1 })
	id, _ := identities(t)
	dialC := w.Client(w.NATHost(nattest.FullCone()), nil)
	d, err := dialC.Open(context.Background(), client.OpenRequest{HostID: "office", TransportMode: quicforward.Mode, TransportData: id.TransportData()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	conn, err := quicforward.Dial(context.Background(), d, id)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.OpenStream(context.Background(), ""); !errors.Is(err, quicforward.ErrRefused) || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("OpenStream: %v", err)
	}
}

// linkDial wraps a world dialer for a host whose registration link, its
// first stream, goes silent when it dials its second, to join a session:
// nothing the host sends on the link reaches the server from then on. After
// cutLink it refuses to dial, so the host cannot register again.
type linkDial struct {
	dial  func(context.Context) (net.Conn, error)
	mu    sync.Mutex
	conns []net.Conn
	cut   bool
}

func (r *linkDial) Dial(ctx context.Context) (net.Conn, error) {
	r.mu.Lock()
	cut := r.cut
	r.mu.Unlock()
	if cut {
		return nil, errors.New("link cut")
	}
	c, err := r.dial(ctx)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.conns = append(r.conns, c)
	if len(r.conns) == 2 {
		r.conns[0].(*nattest.PipeConn).Blackhole()
	}
	r.mu.Unlock()
	return c, nil
}

// cutLink breaks the registration link and refuses later dials.
func (r *linkDial) cutLink() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cut = true
	r.conns[0].(*nattest.PipeConn).Cut()
}

// TestReportFailureKeepsQUIC: when the host's registration link is gone, the
// transport report fails, and the QUIC connection serves on regardless.
func TestReportFailureKeepsQUIC(t *testing.T) {
	reports := make(chan server.TransportReport, 4)
	w := testworld.New(t, testworld.Options{Server: func(c *server.Config) {
		c.OnTransport = func(r server.TransportReport) { reports <- r }
	}})
	hostH := w.NATHost(nattest.PortRestricted())
	rd := &linkDial{dial: w.Dial(hostH)}
	stop, cut := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(cut)
		// Once the host joined, losing its link no longer aborts the
		// session; the punch that follows mostly leaves time to cut it, so
		// that the report fails at once. Should this goroutine be late, the
		// report goes into the silenced link and is lost all the same.
		for w.Server.Stats().Joined == 0 {
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
		rd.cutLink()
	}()
	defer func() {
		close(stop)
		<-cut
	}()
	r := &forwardRig{w: w, targets: &echoTargets{}, ln: newPipeListener(), hostDone: make(chan error, 1), dialDone: make(chan error, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.hostC = w.Client(hostH, func(c *client.Config) { c.Dial = rd.Dial })
	go func() {
		r.hostDone <- quicforward.Serve(ctx, r.hostC, client.Registration{HostID: "office"},
			quicforward.HostConfig{Targets: []string{"svc.test:80"}, Dial: r.targets.dial})
	}()
	testkit.WaitFor(t, "the host to register", func() bool { return len(w.Broker.Snapshot().Hosts) == 1 })
	dialC := w.Client(w.NATHost(nattest.PortRestricted()), nil)
	go func() {
		r.dialDone <- quicforward.Connect(ctx, dialC, quicforward.ConnectConfig{Open: client.OpenRequest{HostID: "office"}, Listener: r.ln})
	}()
	t.Cleanup(func() {
		r.stop(t)
		r.targets.wg.Wait()
	})
	c := r.ln.dial(t)
	defer func() { _ = c.Close() }()
	roundTrip(t, c, []byte("still forwarding"))
	select {
	case rep := <-reports:
		t.Fatalf("report reached the server: %+v", rep)
	default:
	}
}

// TestConnectReopens: when the host goes away and comes back, the dialer's
// next local connection opens a new session.
func TestConnectReopens(t *testing.T) {
	w := testworld.New(t, testworld.Options{})
	targets := &echoTargets{}
	defer targets.wg.Wait()
	serveHost := func() (*client.Client, chan error) {
		ctx := context.Background()
		c := w.Client(w.NATHost(nattest.FullCone()), nil)
		done := make(chan error, 1)
		go func() {
			done <- quicforward.Serve(ctx, c, client.Registration{HostID: "office"},
				quicforward.HostConfig{Targets: []string{"svc.test:80"}, Dial: targets.dial})
		}()
		testkit.WaitFor(t, "the host to register", func() bool { return len(w.Broker.Snapshot().Hosts) == 1 })
		return c, done
	}
	host1, done1 := serveHost()
	ln := newPipeListener()
	ctx, cancel := context.WithCancel(context.Background())
	connected := make(chan error, 1)
	go func() {
		connected <- quicforward.Connect(ctx, w.Client(w.NATHost(nattest.FullCone()), nil),
			quicforward.ConnectConfig{Open: client.OpenRequest{HostID: "office"}, Listener: ln})
	}()
	defer func() {
		cancel()
		if err := <-connected; err != nil {
			t.Errorf("Connect: %v", err)
		}
	}()
	c1 := ln.dial(t)
	roundTrip(t, c1, []byte("one"))
	_ = c1.Close()

	if err := host1.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done1; err != nil {
		t.Fatal(err)
	}
	testkit.WaitFor(t, "the host to unregister", func() bool { return len(w.Broker.Snapshot().Hosts) == 0 })
	host2, done2 := serveHost()
	defer func() {
		_ = host2.Close()
		<-done2
	}()
	testkit.WaitFor(t, "a round trip through the new host", func() bool {
		c := ln.dial(t)
		defer func() { _ = c.Close() }()
		return tryRoundTrip(c, []byte("two"))
	})
}

func tryRoundTrip(c net.Conn, payload []byte) bool {
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	go func() { _, _ = c.Write(payload) }()
	got := make([]byte, len(payload))
	_, err := io.ReadFull(c, got)
	return err == nil && bytes.Equal(got, payload)
}

// TestConnectUnreachableHost: Connect reports a host it cannot reach at
// once and closes the listener.
func TestConnectUnreachableHost(t *testing.T) {
	w := testworld.New(t, testworld.Options{})
	ln := newPipeListener()
	err := quicforward.Connect(context.Background(), w.Client(w.NATHost(nattest.FullCone()), nil),
		quicforward.ConnectConfig{Open: client.OpenRequest{HostID: "nobody"}, Listener: ln})
	var f *proto.Fail
	if !errors.As(err, &f) || f.Code != proto.CodeHostNotFound {
		t.Fatalf("Connect: %v", err)
	}
	select {
	case <-ln.closed:
	default:
		t.Fatal("listener left open")
	}
	if err := quicforward.Connect(context.Background(), nil, quicforward.ConnectConfig{}); err == nil {
		t.Fatal("Connect without listener")
	}
}

func TestHostConfig(t *testing.T) {
	w := testworld.New(t, testworld.Options{})
	c := w.Client(w.NATHost(nattest.FullCone()), nil)
	for _, cfg := range []quicforward.HostConfig{{}, {Targets: []string{"no-port"}}} {
		if err := quicforward.Serve(context.Background(), c, client.Registration{HostID: "office"}, cfg); err == nil {
			t.Fatalf("%+v accepted", cfg)
		}
	}
}
