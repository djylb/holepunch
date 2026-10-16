package client_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/standalone/broker"
	"github.com/djylb/holepunch/standalone/client"
	"github.com/djylb/holepunch/standalone/internal/testworld"
	"github.com/djylb/holepunch/standalone/proto"
	"github.com/djylb/holepunch/standalone/server"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

const echoMode = "udp_echo"

// serve runs c.Serve on a goroutine and returns its result channel; the
// test's cleanup cancels it and checks it returned.
func serve(t *testing.T, c *client.Client, reg client.Registration, h client.Handler) (context.CancelFunc, chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Serve(ctx, reg, h) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return")
		}
	})
	return cancel, done
}

// echo answers the peer's datagrams on the session's filtered socket.
func echo(ctx context.Context, s *client.Session) {
	pc := s.PacketConn()
	buf := make([]byte, 1500)
	for ctx.Err() == nil {
		_ = pc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
		_, _ = pc.WriteTo(buf[:n], from)
	}
}

func ping(t *testing.T, s *client.Session, msg []byte) {
	t.Helper()
	pc := s.PacketConn()
	peer := net.UDPAddrFromAddrPort(s.Result().Path.RemoteAddr)
	buf := make([]byte, 1500)
	for attempt := 0; attempt < 20; attempt++ {
		if _, err := pc.WriteTo(msg, peer); err != nil {
			t.Fatal(err)
		}
		_ = pc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, err := pc.ReadFrom(buf)
		if err == nil && bytes.Equal(buf[:n], msg) {
			_ = pc.SetReadDeadline(time.Time{})
			return
		}
	}
	t.Fatal("no echo")
}

// failCode is the code of the server's *proto.Fail in err's chain, or "".
func failCode(err error) proto.Code {
	var f *proto.Fail
	if errors.As(err, &f) {
		return f.Code
	}
	return ""
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestOpenServe: a dialer opens a session with a registered host and the
// two exchange datagrams over the punched path through the residual filter;
// both see the server's description of the session.
func TestOpenServe(t *testing.T) {
	reports := make(chan server.TransportReport, 1)
	w := testworld.New(t, testworld.Options{
		Broker: func(c *broker.Config) {
			c.Authorize = func(broker.OpenRequest, broker.HostInfo) (proto.AccessPolicy, error) {
				return proto.AccessPolicy{Targets: []string{"127.0.0.1:22"}}, nil
			}
		},
		Server: func(c *server.Config) { c.OnTransport = func(r server.TransportReport) { reports <- r } },
	})
	hostC := w.Client(w.NATHost(nattest.PortRestricted()), nil)
	hostSessions := make(chan *client.Session, 1)
	serve(t, hostC, client.Registration{HostID: "office", Metadata: map[string]string{"os": "linux"}, TransportMode: echoMode},
		func(ctx context.Context, s *client.Session) {
			hostSessions <- s
			if err := s.ReportTransport(true, "echo"); err != nil {
				t.Errorf("report: %v", err)
			}
			echo(ctx, s)
		})
	waitFor(t, func() bool { return len(w.Broker.Snapshot().Hosts) == 1 })

	dialC := w.Client(w.NATHost(nattest.PortRestricted()), nil)
	s, err := dialC.Open(context.Background(), client.OpenRequest{HostID: "office", DialerID: "laptop", Metadata: map[string]string{"user": "ann"}, TransportMode: echoMode})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	ping(t, s, []byte("hello"))

	info := s.Info()
	if s.Role() != protocol.RoleInitiator || info.HostID != "office" || info.DialerID != "laptop" ||
		info.HostMetadata["os"] != "linux" || info.DialerMetadata["user"] != "ann" || len(info.Policy.Targets) != 1 {
		t.Fatalf("dialer info %+v", info)
	}
	info.HostMetadata["os"] = "x"
	if s.Info().HostMetadata["os"] != "linux" {
		t.Fatal("Info shares its maps")
	}
	if res := s.Result(); res.TransportMode != echoMode || res.SessionID != s.ID() || !res.Path.RemoteAddr.IsValid() {
		t.Fatalf("result %+v", res)
	}
	if s.Diagnostics().SessionID != s.ID() || s.Holepunch() == nil {
		t.Fatal("diagnostics")
	}
	if _, ok := s.PacketConn().(interface{ Dropped() uint64 }); !ok {
		t.Fatal("PacketConn is not the residual filter")
	}
	if err := s.ReportTransport(true, ""); !errors.Is(err, client.ErrNoLink) {
		t.Fatalf("dialer report: %v", err)
	}
	hs := <-hostSessions
	if hs.Role() != protocol.RoleResponder || hs.ID() != s.ID() || hs.Info().DialerMetadata["user"] != "ann" {
		t.Fatalf("host session %+v", hs.Info())
	}
	select {
	case r := <-reports:
		if r.SessionID != s.ID() || !r.OK || r.Detail != "echo" || r.HostID != "office" {
			t.Fatalf("report %+v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no transport report")
	}
}

// TestCloseStuckHandler: Close cancels the Handlers' context and
// closes their sessions; a Handler that ignores both cannot hold Close for
// more than its 2 s bound, and is reported.
func TestCloseStuckHandler(t *testing.T) {
	w := testworld.New(t, testworld.Options{})
	hostC := w.Client(w.NATHost(nattest.FullCone()), nil)
	release := make(chan struct{})
	entered := make(chan struct{})
	var returned atomic.Bool
	_, done := serve(t, hostC, client.Registration{HostID: "office"}, func(context.Context, *client.Session) {
		close(entered)
		<-release // ignores its context
		returned.Store(true)
	})
	waitFor(t, func() bool { return len(w.Broker.Snapshot().Hosts) == 1 })
	dialC := w.Client(w.NATHost(nattest.FullCone()), nil)
	s, err := dialC.Open(context.Background(), client.OpenRequest{HostID: "office"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	<-entered

	start := time.Now()
	err = hostC.Close()
	d := time.Since(start)
	// Close waits its 2 s bound, not for the Handler, which only returns
	// once released below; the upper bound is slack for a loaded machine.
	if !errors.Is(err, client.ErrCloseTimeout) || d < 2*time.Second || d > 5*time.Second {
		t.Fatalf("Close: %v after %v", err, d)
	}
	if err2 := hostC.Close(); err2 == nil || err2.Error() != err.Error() {
		t.Fatalf("second Close: %v", err2)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
		done <- nil
	case <-time.After(time.Second):
		t.Fatal("Serve did not return after Close")
	}
	close(release)
	waitFor(t, returned.Load)
	if _, err := hostC.Open(context.Background(), client.OpenRequest{HostID: "office"}); !errors.Is(err, client.ErrClosed) {
		t.Fatalf("Open after Close: %v", err)
	}
	if err := hostC.Serve(context.Background(), client.Registration{HostID: "office"}, func(context.Context, *client.Session) {}); !errors.Is(err, client.ErrClosed) {
		t.Fatalf("Serve after Close: %v", err)
	}
}

// TestCloseCancelsHandler: a Handler that watches its context lets Close
// return at once, without error.
func TestCloseCancelsHandler(t *testing.T) {
	w := testworld.New(t, testworld.Options{})
	hostC := w.Client(w.NATHost(nattest.FullCone()), nil)
	entered := make(chan struct{})
	serve(t, hostC, client.Registration{HostID: "office"}, func(ctx context.Context, s *client.Session) {
		close(entered)
		<-ctx.Done()
	})
	waitFor(t, func() bool { return len(w.Broker.Snapshot().Hosts) == 1 })
	dialC := w.Client(w.NATHost(nattest.FullCone()), nil)
	s, err := dialC.Open(context.Background(), client.OpenRequest{HostID: "office"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	<-entered
	// A Handler left running would hold Close for its 2 s bound and make
	// it fail with ErrCloseTimeout.
	start := time.Now()
	if err := hostC.Close(); err != nil || time.Since(start) >= 2*time.Second {
		t.Fatalf("Close: %v after %v", err, time.Since(start))
	}
}

// recordingDial wraps a world dialer and keeps every stream it opened.
type recordingDial struct {
	dial  func(context.Context) (net.Conn, error)
	mu    sync.Mutex
	conns []net.Conn
}

func (r *recordingDial) Dial(ctx context.Context) (net.Conn, error) {
	c, err := r.dial(ctx)
	if err == nil {
		r.mu.Lock()
		r.conns = append(r.conns, c)
		r.mu.Unlock()
	}
	return c, err
}

func (r *recordingDial) first() *nattest.PipeConn {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.conns[0].(*nattest.PipeConn)
}

// TestServeReregisters: a host whose link went silent (blackholed, so the
// server still believes it alive) comes back under its ID with the
// credential of its last registration, and serves again.
func TestServeReregisters(t *testing.T) {
	w := testworld.New(t, testworld.Options{Server: func(c *server.Config) { c.Heartbeat = time.Second }})
	h := w.NATHost(nattest.FullCone())
	rd := &recordingDial{dial: w.Dial(h)}
	hostC := w.Client(h, func(c *client.Config) { c.Dial = rd.Dial })
	serve(t, hostC, client.Registration{HostID: "office", TransportMode: echoMode}, func(ctx context.Context, s *client.Session) { echo(ctx, s) })
	waitFor(t, func() bool { return len(w.Broker.Snapshot().Hosts) == 1 })
	dialC := w.Client(w.NATHost(nattest.FullCone()), nil)
	session := func(msg string) {
		s, err := dialC.Open(context.Background(), client.OpenRequest{HostID: "office", TransportMode: echoMode})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.Close() }()
		ping(t, s, []byte(msg))
	}
	session("first") // the host reads its link: the Incoming came through
	rd.first().Blackhole()
	waitFor(t, func() bool { return w.Server.Stats().Registered == 2 && len(w.Broker.Snapshot().Hosts) == 1 })
	session("again")
}

// TestServeErrors: a refusal retrying cannot cure ends Serve; a second
// concurrent Serve is refused.
func TestServeErrors(t *testing.T) {
	w := testworld.New(t, testworld.Options{Server: func(c *server.Config) { c.AuthToken = "secret" }})
	h := w.NATHost(nattest.FullCone())
	bad := w.Client(h, nil)
	err := bad.Serve(context.Background(), client.Registration{HostID: "office"}, func(context.Context, *client.Session) {})
	if failCode(err) != proto.CodeUnauthorized {
		t.Fatalf("Serve without token: %v", err)
	}
	if _, err := bad.Open(context.Background(), client.OpenRequest{HostID: "office"}); failCode(err) != proto.CodeUnauthorized {
		t.Fatalf("Open without token: %v", err)
	}
	if err := bad.Serve(context.Background(), client.Registration{HostID: "bad id"}, func(context.Context, *client.Session) {}); !errors.Is(err, proto.ErrInvalid) {
		t.Fatalf("bad id: %v", err)
	}
	if err := bad.Serve(context.Background(), client.Registration{HostID: "office"}, nil); !errors.Is(err, proto.ErrInvalid) {
		t.Fatalf("nil handler: %v", err)
	}

	good := w.Client(h, func(c *client.Config) { c.AuthToken = " secret " })
	serve(t, good, client.Registration{HostID: "office"}, func(context.Context, *client.Session) {})
	waitFor(t, func() bool { return len(w.Broker.Snapshot().Hosts) == 1 })
	if err := good.Serve(context.Background(), client.Registration{HostID: "other"}, func(context.Context, *client.Session) {}); !errors.Is(err, client.ErrServing) {
		t.Fatalf("second Serve: %v", err)
	}
	other := w.Client(w.NATHost(nattest.FullCone()), func(c *client.Config) { c.AuthToken = "secret" })
	if err := other.Serve(context.Background(), client.Registration{HostID: "office"}, func(context.Context, *client.Session) {}); failCode(err) != proto.CodeHostExists {
		t.Fatalf("stolen ID: %v", err)
	}
	if _, err := other.Open(context.Background(), client.OpenRequest{HostID: "nobody"}); failCode(err) != proto.CodeHostNotFound {
		t.Fatalf("unknown host: %v", err)
	}
}

// panickyAsError is a dial error whose As method panics.
type panickyAsError struct{}

func (panickyAsError) Error() string { return "unreachable" }
func (panickyAsError) As(_ any) bool { panic("As exploded") }

// TestServeRetriesUntilCanceled: an unreachable server is retried with a
// backoff, and canceling ends Serve with nil. The dial error's methods are
// the caller's code; one that panics is a transient error like any other.
func TestServeRetriesUntilCanceled(t *testing.T) {
	var dials atomic.Int32
	c, err := client.New(client.Config{
		Server: "holepunchd.test:1",
		Dial: func(context.Context) (net.Conn, error) {
			dials.Add(1)
			return nil, panickyAsError{}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	// Dials at 0 s and 1 s, the next one only at 3 s (backoff 1 s, then
	// 2 s): 2.5 s leaves slack on both sides.
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	if err := c.Serve(ctx, client.Registration{HostID: "office"}, func(context.Context, *client.Session) {}); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if n := dials.Load(); n != 2 {
		t.Fatalf("%d dials in 2.5 s, want 2 (backoff 1 s, then 2 s)", n)
	}
}

func TestDialFailures(t *testing.T) {
	for name, dial := range map[string]func(context.Context) (net.Conn, error){
		"panic": func(context.Context) (net.Conn, error) { panic("dial boom") },
		"nil":   func(context.Context) (net.Conn, error) { return nil, nil },
		"error": func(context.Context) (net.Conn, error) { return nil, errors.New("down") },
		"tls": func(context.Context) (net.Conn, error) {
			a, b := net.Pipe()
			_ = b.Close()
			return a, nil
		},
	} {
		c, err := client.New(client.Config{Server: "h:1", Dial: dial, HandshakeTimeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Open(context.Background(), client.OpenRequest{HostID: "x"}); err == nil {
			t.Fatalf("%s: Open succeeded", name)
		}
		_ = c.Close()
	}
}

func TestNew(t *testing.T) {
	for _, cfg := range []client.Config{
		{},
		{Server: "no-port"},
		{Server: "h:1", HandshakeTimeout: -1},
		{Dial: func(context.Context) (net.Conn, error) { return nil, nil }},
	} {
		if _, err := client.New(cfg); err == nil {
			t.Fatalf("%+v accepted", cfg)
		}
	}
	c, err := client.New(client.Config{Server: "h:1"})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
}
