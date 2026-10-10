package server

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/djylb/holepunch/controlwire"
	"github.com/djylb/holepunch/coord"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/standalone/broker"
	"github.com/djylb/holepunch/standalone/internal/tlsid"
	"github.com/djylb/holepunch/standalone/proto"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

const token = "secret"

type rig struct {
	t      *testing.T
	b      *broker.Broker
	s      *Server
	client *tls.Config
	net    *nattest.Network // buffered pipes, like TCP: a frame nobody reads yet does not block its writer
}

func newRig(t *testing.T, mutate func(*Config)) *rig {
	t.Helper()
	b, err := broker.New(broker.Config{Coord: coord.Config{AllowUnverifiedTargets: true}})
	if err != nil {
		t.Fatal(err)
	}
	cert, pin, err := tlsid.New("holepunchd.test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Broker: b, AuthToken: " " + token + " ", TLS: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}}
	if mutate != nil {
		mutate(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	n := nattest.NewNetwork()
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
		_ = b.Close()
		_ = n.Close()
	})
	return &rig{t: t, b: b, s: s, net: n, client: &tls.Config{
		MinVersion: tls.VersionTLS13, ServerName: "holepunchd.test", InsecureSkipVerify: true, VerifyPeerCertificate: tlsid.VerifyPin(pin),
	}}
}

// pipe returns the two ends of a buffered stream.
func (r *rig) pipe() (net.Conn, net.Conn) {
	a, b := r.net.Pipe(nattest.PipeConfig{})
	return a, b
}

// dial opens a TLS stream to the server through ServeConn.
func (r *rig) dial() net.Conn {
	r.t.Helper()
	a, b := r.pipe()
	if err := r.s.ServeConn(b); err != nil {
		r.t.Fatal(err)
	}
	c := tls.Client(a, r.client)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.HandshakeContext(ctx); err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { _ = a.Close() })
	return c
}

func send(t *testing.T, c net.Conn, m proto.Message) {
	t.Helper()
	if err := proto.Write(c, m, 5*time.Second); err != nil {
		t.Fatal(err)
	}
}

func expect[T proto.Message](t *testing.T, c net.Conn) T {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m, err := proto.Expect[T](ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func expectFail(t *testing.T, c net.Conn, code proto.Code) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m, err := proto.Read(ctx, c)
	if err != nil {
		t.Fatalf("got %v, want fail %s", err, code)
	}
	switch f := m.(type) {
	case *proto.Fail:
		if f.Code != code {
			t.Fatalf("got fail %s, want %s", f.Code, code)
		}
	default:
		t.Fatalf("got %v, want fail %s", m, code)
	}
	if _, err := proto.Read(ctx, c); err == nil {
		t.Fatal("stream open after Fail")
	}
}

// punchStart reads the next frame and checks that it is holepunch's
// punch_start: the stream has become a control connection.
func punchStart(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var hdr [8]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		t.Fatal(err)
	}
	if hdr[0] != 'h' || hdr[1] != 'p' || controlwire.Type(hdr[3]) != controlwire.TypePunchStart {
		t.Fatalf("header % x", hdr)
	}
	go func() { _, _ = io.Copy(io.Discard, c) }()
}

// register2 registers a host over a plain stream (a server without TLS).
func (r *rig) register2(t *testing.T) {
	t.Helper()
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	if err := r.s.ServeConn(b); err != nil {
		t.Fatal(err)
	}
	send(t, a, &proto.Register{HostID: "plain", AuthToken: token})
	expect[*proto.Registered](t, a)
}

// register registers a host and returns its link.
func (r *rig) register(id string) (net.Conn, *proto.Registered) {
	r.t.Helper()
	c := r.dial()
	send(r.t, c, &proto.Register{HostID: id, AuthToken: token})
	return c, expect[*proto.Registered](r.t, c)
}

// TestFlow: register, open, Incoming on the link, join; both streams answer
// SessionInfo and carry punch_start next.
func TestFlow(t *testing.T) {
	r := newRig(t, nil)
	hl, regd := r.register("office")
	if regd.Credential == "" || regd.HeartbeatMs != uint32(DefaultHeartbeat/time.Millisecond) {
		t.Fatalf("registered %+v", regd)
	}
	waitFor(t, func() bool { return r.s.Stats().Hosts == 1 })

	dc := r.dial()
	send(t, dc, &proto.Open{HostID: "office", DialerID: "laptop", AuthToken: token})
	info := expect[*proto.SessionInfo](t, dc)
	if info.HostID != "office" || info.DialerID != "laptop" {
		t.Fatalf("info %+v", info)
	}
	punchStart(t, dc)
	in := expect[*proto.Incoming](t, hl)
	if in.SessionID != info.SessionID {
		t.Fatalf("incoming %+v", in)
	}
	jc := r.dial()
	send(t, jc, &proto.Join{SessionID: in.SessionID, Ticket: in.Ticket})
	if j := expect[*proto.SessionInfo](t, jc); j.SessionID != info.SessionID {
		t.Fatalf("join info %+v", j)
	}
	punchStart(t, jc)
	st := r.s.Stats()
	if st.Registered != 1 || st.Opened != 1 || st.Joined != 1 || st.Conns != 1 || st.Refused != 0 {
		t.Fatalf("stats %+v", st)
	}
	cs, ok := r.b.Coordinator().Lookup(info.SessionID)
	if !ok || !cs.Snapshot().Attached[0] || !cs.Snapshot().Attached[1] {
		t.Fatal("streams not attached")
	}

	// A second join with the same ticket is refused.
	jc2 := r.dial()
	send(t, jc2, &proto.Join{SessionID: in.SessionID, Ticket: in.Ticket})
	expectFail(t, jc2, proto.CodeSessionNotFound)
}

func TestAuthorization(t *testing.T) {
	var seen []AuthRequest
	var mu sync.Mutex
	r := newRig(t, func(c *Config) {
		c.Authorize = func(req AuthRequest) error {
			mu.Lock()
			seen = append(seen, req)
			mu.Unlock()
			switch req.HostID {
			case "denied":
				return errors.New("no")
			case "boom":
				panic("authorize boom")
			}
			return nil
		}
	})
	for _, m := range []proto.Message{
		&proto.Register{HostID: "office"},
		&proto.Register{HostID: "office", AuthToken: "wrong"},
		&proto.Open{HostID: "office", AuthToken: token + "x"},
		&proto.Register{HostID: "denied", AuthToken: token},
		&proto.Open{HostID: "boom", AuthToken: token},
	} {
		c := r.dial()
		send(t, c, m)
		expectFail(t, c, proto.CodeUnauthorized)
	}
	if st := r.s.Stats(); st.Panics != 1 || st.Refused != 5 {
		t.Fatalf("stats %+v", st)
	}
	r.register("office")
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 3 {
		t.Fatalf("Authorize called %d times; the token check comes first", len(seen))
	}
	last := seen[2]
	if last.Scope != ScopeRegister || last.Token != token || last.Remote == nil || last.TLS == nil || !last.TLS.HandshakeComplete {
		t.Fatalf("auth request %+v", last)
	}
}

// TestNoToken: an empty AuthToken disables the check.
func TestNoToken(t *testing.T) {
	r := newRig(t, func(c *Config) { c.AuthToken = "  " })
	c := r.dial()
	send(t, c, &proto.Register{HostID: "office"})
	expect[*proto.Registered](t, c)
}

func TestRefusals(t *testing.T) {
	r := newRig(t, nil)
	r.register("office")
	cases := []struct {
		m    proto.Message
		code proto.Code
	}{
		{&proto.Heartbeat{}, proto.CodeInvalidRequest},
		{&proto.Open{HostID: "nobody", AuthToken: token}, proto.CodeHostNotFound},
		{&proto.Register{HostID: "office", AuthToken: token}, proto.CodeHostExists},
		{&proto.Join{SessionID: "nope", Ticket: "t"}, proto.CodeSessionNotFound},
	}
	for _, c := range cases {
		conn := r.dial()
		send(t, conn, c.m)
		expectFail(t, conn, c.code)
	}
	conn := r.dial()
	_, _ = conn.Write([]byte{proto.Version, 0xee, 0, 2, '{', '}'})
	expectFail(t, conn, proto.CodeInvalidRequest)
}

// TestHeartbeats: the server answers heartbeats, passes transport reports
// on, and drops a link silent for three intervals, which unregisters the
// host.
func TestHeartbeats(t *testing.T) {
	reports := make(chan TransportReport, 2)
	r := newRig(t, func(c *Config) {
		c.Heartbeat = time.Second
		c.OnTransport = func(rep TransportReport) {
			reports <- rep
			if !rep.OK {
				panic("report boom")
			}
		}
	})
	hl, regd := r.register("office")
	if regd.HeartbeatMs != 1000 {
		t.Fatalf("heartbeat %d", regd.HeartbeatMs)
	}
	send(t, hl, &proto.Heartbeat{})
	expect[*proto.Heartbeat](t, hl)
	send(t, hl, &proto.Transport{SessionID: "s1", OK: true, Detail: "quic"})
	send(t, hl, &proto.Transport{SessionID: "s2"})
	for _, want := range []TransportReport{{"office", "s1", true, "quic"}, {"office", "s2", false, ""}} {
		select {
		case got := <-reports:
			if got != want {
				t.Fatalf("report %+v", got)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no report")
		}
	}
	start := time.Now()
	waitFor(t, func() bool { return len(r.b.Snapshot().Hosts) == 0 })
	if d := time.Since(start); d < 2*time.Second || d > 4*time.Second {
		t.Fatalf("silent link dropped after %v", d)
	}
	waitFor(t, func() bool { return r.s.Stats().Hosts == 0 && r.s.Stats().Panics == 1 })
}

// TestLinkProtocolError: anything but heartbeats and reports ends a link.
func TestLinkProtocolError(t *testing.T) {
	r := newRig(t, nil)
	hl, _ := r.register("office")
	send(t, hl, &proto.Open{HostID: "x"})
	waitFor(t, func() bool { return len(r.b.Snapshot().Hosts) == 0 })
}

// TestTakeoverRevokesLink: a registration with the credential takes the ID
// over and the server closes the old link.
func TestTakeoverRevokesLink(t *testing.T) {
	r := newRig(t, nil)
	old, regd := r.register("office")
	c := r.dial()
	send(t, c, &proto.Register{HostID: "office", AuthToken: token, Credential: regd.Credential})
	expect[*proto.Registered](t, c)
	_ = old.SetReadDeadline(time.Now().Add(5 * time.Second))
	var ne net.Error
	if _, err := old.Read(make([]byte, 1)); err == nil {
		t.Fatal("old link still open")
	} else if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("old link not closed")
	}
}

// TestHandshakeTimeout: a client that never sends its request is dropped.
func TestHandshakeTimeout(t *testing.T) {
	r := newRig(t, func(c *Config) { c.HandshakeTimeout = 100 * time.Millisecond })
	c := r.dial()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("read data")
	}
	waitFor(t, func() bool { return r.s.Stats().HandshakeFailed == 1 && r.s.Stats().Conns == 0 })

	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	if err := r.s.ServeConn(b); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return r.s.Stats().HandshakeFailed == 2 })
}

// memListener is an in-memory net.Listener.
type memListener struct {
	conns  chan net.Conn
	errs   chan error
	closed chan struct{}
	once   sync.Once
}

func newMemListener() *memListener {
	return &memListener{conns: make(chan net.Conn), errs: make(chan error, 4), closed: make(chan struct{})}
}

func (l *memListener) Accept() (net.Conn, error) {
	select {
	case err := <-l.errs:
		return nil, err
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *memListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *memListener) Addr() net.Addr { return &net.TCPAddr{} }

// TestServeAndClose: Serve retries transient accept errors, serves
// connections and returns nil on Close, which closes the listener and the
// connections the server holds.
func TestServeAndClose(t *testing.T) {
	r := newRig(t, nil)
	l := newMemListener()
	done := make(chan error, 1)
	go func() { done <- r.s.Serve(l) }()
	l.errs <- errors.New("too many open files")
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	l.conns <- b
	waitFor(t, func() bool { return r.s.Stats().Accepted == 1 })
	if err := r.s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Serve: %v", err)
	}
	select {
	case <-l.closed:
	default:
		t.Fatal("listener open")
	}
	if _, err := a.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection open")
	}
	c, d := net.Pipe()
	defer func() { _ = d.Close() }()
	if err := r.s.ServeConn(c); !errors.Is(err, ErrClosed) {
		t.Fatalf("ServeConn after close: %v", err)
	}
	if err := r.s.Serve(newMemListener()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Serve after close: %v", err)
	}
}

// TestServeListenerError: a listener closed under Serve is an error.
func TestServeListenerError(t *testing.T) {
	r := newRig(t, nil)
	l := newMemListener()
	_ = l.Close()
	if err := r.s.Serve(l); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Serve: %v", err)
	}
}

func TestMaxConns(t *testing.T) {
	r := newRig(t, func(c *Config) { c.MaxConns = 1 })
	r.register("office")
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	if err := r.s.ServeConn(b); !errors.Is(err, ErrBusy) {
		t.Fatalf("over the limit: %v", err)
	}
	if _, err := a.Read(make([]byte, 1)); err == nil {
		t.Fatal("refused connection open")
	}
	if err := r.s.ServeConn(nil); err == nil {
		t.Fatal("nil connection served")
	}
}

func TestNew(t *testing.T) {
	b, err := broker.New(broker.Config{Coord: coord.Config{AllowUnverifiedTargets: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	for _, cfg := range []Config{
		{},
		{Broker: b, Heartbeat: time.Millisecond},
		{Broker: b, Heartbeat: time.Hour},
		{Broker: b, WriteTimeout: -1},
	} {
		if _, err := New(cfg); err == nil {
			t.Fatalf("%+v accepted", cfg)
		}
	}
}

// TestPanicEndsOneConnection: a panic while serving a connection ends that
// connection only, and is counted.
func TestPanicEndsOneConnection(t *testing.T) {
	r := newRig(t, func(c *Config) { c.TLS = nil })
	r.s.handle(context.Background(), &panicConn{})
	if st := r.s.Stats(); st.Panics != 1 {
		t.Fatalf("stats %+v", st)
	}
	r.register2(t)
}

// panicConn panics on every call but Close.
type panicConn struct{ net.Conn }

func (*panicConn) Read(_ []byte) (int, error)         { panic("read boom") }
func (*panicConn) Write(_ []byte) (int, error)        { panic("write boom") }
func (*panicConn) SetDeadline(_ time.Time) error      { return nil }
func (*panicConn) SetReadDeadline(_ time.Time) error  { return nil }
func (*panicConn) SetWriteDeadline(_ time.Time) error { return nil }
func (*panicConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (*panicConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (*panicConn) Close() error                       { return nil }

func TestCodeOf(t *testing.T) {
	panicked := life.Safe("test", func() { panic(broker.ErrClosed) })
	if !errors.Is(panicked, broker.ErrClosed) || codeOf(panicked) != proto.CodeInternal {
		t.Fatalf("a panic wrapping ErrClosed maps to %s", codeOf(panicked))
	}
	for err, want := range map[error]proto.Code{
		broker.ErrClosed:          proto.CodeShutdown,
		coord.ErrClosed:           proto.CodeShutdown,
		broker.ErrInvalidRequest:  proto.CodeInvalidRequest,
		broker.ErrHostNotFound:    proto.CodeHostNotFound,
		broker.ErrHostExists:      proto.CodeHostExists,
		broker.ErrRegistryFull:    proto.CodeBusy,
		coord.ErrBusy:             proto.CodeBusy,
		broker.ErrRefused:         proto.CodeUnauthorized,
		broker.ErrSessionNotFound: proto.CodeSessionNotFound,
		&protocol.ValidationError{Reason: protocol.ReasonInvalidArgument}: proto.CodeInvalidRequest,
		errors.New("other"): proto.CodeInternal,
	} {
		if got := codeOf(err); got != want {
			t.Errorf("%v: %s, want %s", err, got, want)
		}
	}
}

func TestSanitize(t *testing.T) {
	long := strings.Repeat("é", proto.MaxTextLen)
	got := sanitize("a\nb\x00c" + long)
	if len(got) > proto.MaxTextLen || strings.ContainsAny(got, "\n\x00") {
		t.Fatalf("%q", got)
	}
}

func TestClientKey(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	if got := clientKey(a); got != "addr:pipe" {
		t.Fatalf("%q", got)
	}
	c := &panicConn{}
	if got := clientKey(c); !strings.HasPrefix(got, "ip:") {
		t.Fatalf("%q", got)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
