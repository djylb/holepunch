package quicforward_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/standalone/client"
	"github.com/djylb/holepunch/standalone/internal/testworld"
	"github.com/djylb/holepunch/standalone/quicforward"
	"github.com/djylb/holepunch/standalone/server"
)

// pipeListener is an in-memory net.Listener: dial hands it one end of a
// net.Pipe.
type pipeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }

func (l *pipeListener) dial(t *testing.T) net.Conn {
	t.Helper()
	a, b := net.Pipe()
	select {
	case l.conns <- b:
		return a
	case <-l.closed:
		t.Fatal("listener closed")
	case <-time.After(5 * time.Second):
		t.Fatal("listener not accepting")
	}
	return nil
}

// halfConn is one end of an in-memory stream that, unlike net.Pipe, can be
// half-closed, like the TCP connections the host dials in production.
type halfConn struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func halfPipe() (*halfConn, *halfConn) {
	ar, bw := io.Pipe()
	br, aw := io.Pipe()
	return &halfConn{r: ar, w: aw}, &halfConn{r: br, w: bw}
}

func (c *halfConn) Read(p []byte) (int, error)         { return c.r.Read(p) }
func (c *halfConn) Write(p []byte) (int, error)        { return c.w.Write(p) }
func (c *halfConn) CloseWrite() error                  { return c.w.Close() }
func (c *halfConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *halfConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *halfConn) SetDeadline(_ time.Time) error      { return nil }
func (c *halfConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *halfConn) SetWriteDeadline(_ time.Time) error { return nil }
func (c *halfConn) Close() error {
	_ = c.w.Close()
	return c.r.Close()
}

// echoTargets serves every target dial with an in-memory echo service that
// ends when its client half-closes, and records the addresses dialed.
type echoTargets struct {
	mu     sync.Mutex
	dialed []string
	wg     sync.WaitGroup
}

func (e *echoTargets) dial(_ context.Context, address string) (net.Conn, error) {
	e.mu.Lock()
	e.dialed = append(e.dialed, address)
	e.mu.Unlock()
	a, b := halfPipe()
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer func() { _ = b.Close() }()
		_, _ = io.Copy(b, b)
	}()
	return a, nil
}

func (e *echoTargets) addresses() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.dialed...)
}

// forwardRig runs a quicforward host and dialer in a World.
type forwardRig struct {
	w        *testworld.World
	targets  *echoTargets
	ln       *pipeListener
	cancel   context.CancelFunc
	hostDone chan error
	dialDone chan error
	hostC    *client.Client
}

func startForward(t *testing.T, w *testworld.World, hostH, dialH *nattest.Host, hcfg quicforward.HostConfig) *forwardRig {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &forwardRig{w: w, targets: &echoTargets{}, ln: newPipeListener(), cancel: cancel,
		hostDone: make(chan error, 1), dialDone: make(chan error, 1)}
	if hcfg.Targets == nil {
		hcfg.Targets = []string{"svc.test:80"}
	}
	if hcfg.Dial == nil {
		hcfg.Dial = r.targets.dial
	}
	r.hostC = w.Client(hostH, nil)
	go func() { r.hostDone <- quicforward.Serve(ctx, r.hostC, client.Registration{HostID: "office"}, hcfg) }()
	waitFor(t, 5*time.Second, func() bool { return len(w.Broker.Snapshot().Hosts) == 1 })
	dialC := w.Client(dialH, nil)
	go func() {
		r.dialDone <- quicforward.Connect(ctx, dialC, quicforward.ConnectConfig{
			Open: client.OpenRequest{HostID: "office", DialerID: "laptop"}, Listener: r.ln,
		})
	}()
	t.Cleanup(func() {
		r.stop(t)
		r.targets.wg.Wait()
	})
	return r
}

func (r *forwardRig) stop(t *testing.T) {
	r.cancel()
	for name, ch := range map[string]chan error{"Serve": r.hostDone, "Connect": r.dialDone} {
		select {
		case err := <-ch:
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			ch <- nil
		case <-time.After(5 * time.Second):
			t.Errorf("%s did not return", name)
		}
	}
}

// roundTrip sends payload through a forwarded connection and checks the
// echo.
func roundTrip(t *testing.T, c net.Conn, payload []byte) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	errc := make(chan error, 1)
	go func() {
		_, err := c.Write(payload)
		errc <- err
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("echo differs from the payload")
	}
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestForwardSessionEndToEnd: two clients behind simulated NATs punch
// through the standalone server and forward TCP over QUIC on the punched
// path, for port-restricted cones on both sides, a cone facing a
// sequential symmetric NAT, and two hosts in the same LAN behind a
// hairpinning NAT.
func TestForwardSessionEndToEnd(t *testing.T) {
	cases := []struct {
		name         string
		host, dialer nattest.NATConfig
		sameLAN      bool
	}{
		{name: "cone_cone", host: nattest.PortRestricted(), dialer: nattest.PortRestricted()},
		{name: "cone_symmetric", host: nattest.PortRestricted(), dialer: nattest.SymmetricSeq(1)},
		{name: "same_lan", host: testworld.Hairpin(nattest.PortRestricted()), sameLAN: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			w := testworld.New(t, testworld.Options{})
			nat := w.Net.NAT(tc.host)
			hostH := nat.Host()
			dialH := nat.Host()
			if !tc.sameLAN {
				dialH = w.NATHost(tc.dialer)
			}
			r := startForward(t, w, hostH, dialH, quicforward.HostConfig{})
			c := r.ln.dial(t)
			defer func() { _ = c.Close() }()
			roundTrip(t, c, []byte("ping"))
			big := make([]byte, 256<<10)
			_, _ = rand.Read(big)
			roundTrip(t, c, big)
			c2 := r.ln.dial(t)
			defer func() { _ = c2.Close() }()
			roundTrip(t, c2, []byte("second stream"))
			if got := r.targets.addresses(); len(got) != 2 || got[0] != "svc.test:80" {
				t.Fatalf("targets dialed %v", got)
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Fatalf("took %v", d)
			}
			t.Logf("%s: forwarded in %v", tc.name, time.Since(start))
		})
	}
}

// TestTransportReport: the host reports the QUIC transport to the server.
func TestTransportReport(t *testing.T) {
	reports := make(chan server.TransportReport, 4)
	w := testworld.New(t, testworld.Options{Server: func(c *server.Config) {
		c.OnTransport = func(r server.TransportReport) { reports <- r }
	}})
	r := startForward(t, w, w.NATHost(nattest.FullCone()), w.NATHost(nattest.FullCone()), quicforward.HostConfig{})
	c := r.ln.dial(t)
	defer func() { _ = c.Close() }()
	roundTrip(t, c, []byte("x"))
	select {
	case rep := <-reports:
		if !rep.OK || rep.HostID != "office" || rep.Detail != quicforward.Mode {
			t.Fatalf("report %+v", rep)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no transport report")
	}
}
