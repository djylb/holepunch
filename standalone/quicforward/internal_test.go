package quicforward

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/djylb/holepunch"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/standalone/client"
	"github.com/djylb/holepunch/standalone/internal/testworld"
	"github.com/djylb/holepunch/standalone/proto"
)

func TestStreamFrames(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFrame(&buf, streamRequest{Target: "a.test:1"}); err != nil {
		t.Fatal(err)
	}
	var req streamRequest
	if err := readFrame(&buf, &req); err != nil || req.Target != "a.test:1" {
		t.Fatalf("%+v %v", req, err)
	}
	if err := writeFrame(&buf, streamRequest{Target: strings.Repeat("x", maxStreamFrame)}); err == nil {
		t.Fatal("oversized frame written")
	}
	if err := readFrame(bytes.NewReader([]byte{0xff, 0xff}), &req); err == nil {
		t.Fatal("oversized frame read")
	}
	if err := readFrame(bytes.NewReader([]byte{0, 5, '{'}), &req); err == nil {
		t.Fatal("truncated frame read")
	}
	if err := readFrame(bytes.NewReader(nil), &req); err == nil {
		t.Fatal("empty stream read")
	}
	if err := writeFrame(&buf, make(chan int)); err == nil {
		t.Fatal("unencodable value written")
	}
}

func TestResolve(t *testing.T) {
	cfg, err := HostConfig{Targets: []string{"A.test:1", "[::1]:22"}}.normalize()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Dial == nil || cfg.Logger == nil || cfg.DialTimeout != DefaultDialTimeout {
		t.Fatalf("defaults %+v", cfg)
	}
	open := proto.AccessPolicy{}
	only := proto.AccessPolicy{Targets: []string{"[::1]:22"}}
	for _, c := range []struct {
		req    string
		policy proto.AccessPolicy
		want   string
	}{
		{"", open, "a.test:1"},
		{"a.TEST:01", open, "a.test:1"},
		{"[0:0::1]:22", open, "[::1]:22"},
		{"[::1]:22", only, "[::1]:22"},
		{"", only, ""},
		{"b.test:1", open, ""},
		{"nonsense", open, ""},
	} {
		got, err := cfg.resolve(c.req, c.policy)
		if got != c.want || (c.want == "") != (err != nil) {
			t.Errorf("%q %v: %q %v", c.req, c.policy, got, err)
		}
	}
}

func TestPeerPin(t *testing.T) {
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if pin, err := peerPin(id.TransportData()); err != nil || pin != id.pin {
		t.Fatalf("%q %v", pin, err)
	}
	for _, bad := range []string{"", id.pin, "sha256:", "sha256:zz", "md5:" + id.pin} {
		if _, err := peerPin([]byte(bad)); !errors.Is(err, ErrTransport) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestSameAddr(t *testing.T) {
	want := netip.MustParseAddrPort("203.0.113.7:4000")
	for a, ok := range map[net.Addr]bool{
		&net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4000}:        true,
		&net.UDPAddr{IP: net.ParseIP("::ffff:203.0.113.7"), Port: 4000}: true,
		&net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4001}:        false,
		&net.UDPAddr{IP: net.ParseIP("203.0.113.8"), Port: 4000}:        false,
		&net.UnixAddr{Name: "x", Net: "unix"}:                           false,
	} {
		if sameAddr(a, want) != ok {
			t.Errorf("%v: %v", a, !ok)
		}
	}
	if sameAddr(nil, want) {
		t.Fatal("nil address matched")
	}
}

func TestQUICConfig(t *testing.T) {
	c := quicConfig(holepunch.Result{})
	if c.HandshakeIdleTimeout != defaultTransportTimeout || c.MaxIdleTimeout != defaultIdleTimeout || c.KeepAlivePeriod != defaultIdleTimeout/3 {
		t.Fatalf("defaults %+v", c)
	}
	c = quicConfig(holepunch.Result{TransportTimeout: 3 * time.Second, Path: holepunch.Path{Keepalive: holepunch.KeepaliveAdvice{Interval: 10 * time.Second, Timeout: 30 * time.Second}}})
	if c.HandshakeIdleTimeout != 3*time.Second || c.MaxIdleTimeout != 30*time.Second || c.KeepAlivePeriod != 10*time.Second {
		t.Fatalf("advice %+v", c)
	}
}

func TestPause(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if pause(ctx, time.Hour) {
		t.Fatal("pause outlived its context")
	}
	if !pause(context.Background(), time.Millisecond) {
		t.Fatal("pause interrupted")
	}
}

// FuzzStreamRequest: whatever a dialer writes as a stream's request, the
// host never panics and never resolves a target outside its list.
func FuzzStreamRequest(f *testing.F) {
	var buf bytes.Buffer
	_ = writeFrame(&buf, streamRequest{Target: "a.test:1"})
	f.Add(buf.Bytes())
	f.Add([]byte{0, 2, '{', '}'})
	f.Add([]byte{0xff, 0xff})
	cfg, err := HostConfig{Targets: []string{"a.test:1", "[::1]:22"}}.normalize()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var req streamRequest
		if readFrame(bytes.NewReader(data), &req) != nil {
			return
		}
		target, err := cfg.resolve(req.Target, proto.AccessPolicy{})
		if err == nil && target != "a.test:1" && target != "[::1]:22" {
			t.Fatalf("resolved %q", target)
		}
	})
}

// TestIdentityTLS: each side accepts only the pinned peer, and no
// connection can be resumed: the host issues no session ticket, so a
// client with a session cache still makes a full handshake, pin check
// included, every time.
func TestIdentityTLS(t *testing.T) {
	host, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	impostor, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	n := nattest.NewNetwork()
	defer func() { _ = n.Close() }()
	type outcome struct {
		state                tls.ConnectionState
		clientErr, serverErr error
	}
	handshake := func(server, client *tls.Config) outcome {
		a, b := n.Pipe(nattest.PipeConfig{})
		defer func() { _ = a.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srvErr := make(chan error, 1)
		go func() {
			defer func() { _ = b.Close() }()
			srv := tls.Server(b, server)
			err := srv.HandshakeContext(ctx)
			if err == nil {
				// A byte after the handshake: the client reads it, and with it
				// any session ticket the server sent first.
				_, err = srv.Write([]byte{1})
			}
			srvErr <- err
		}()
		cl := tls.Client(a, client)
		err := cl.HandshakeContext(ctx)
		if err == nil {
			_ = cl.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, err = cl.Read(make([]byte, 1))
		}
		return outcome{cl.ConnectionState(), err, <-srvErr}
	}

	server := host.serverTLS(dialer.pin)
	if !server.SessionTicketsDisabled {
		t.Fatal("host issues session tickets")
	}
	cache := tls.NewLRUClientSessionCache(4)
	for range 2 {
		cfg := dialer.clientTLS(host.pin)
		cfg.ClientSessionCache = cache
		o := handshake(server, cfg)
		if o.clientErr != nil || o.serverErr != nil || o.state.DidResume {
			t.Fatalf("pinned peers: client %v, server %v, resumed %v", o.clientErr, o.serverErr, o.state.DidResume)
		}
	}
	if o := handshake(impostor.serverTLS(dialer.pin), dialer.clientTLS(host.pin)); o.clientErr == nil {
		t.Fatal("dialer accepted an impostor host")
	}
	if o := handshake(server, impostor.clientTLS(host.pin)); o.serverErr == nil {
		t.Fatal("host accepted an impostor dialer")
	}
}

// quicPair punches a quicforward session in a World and returns both ends
// of its QUIC connection; the host end accepts no stream.
func quicPair(t *testing.T) (host, dial *Conn) {
	t.Helper()
	w := testworld.New(t, testworld.Options{})
	hostID, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dialID, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hostC := w.Client(w.NATHost(nattest.FullCone()), nil)
	ctx, cancel := context.WithCancel(context.Background())
	sessions := make(chan *client.Session, 1)
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = hostC.Serve(ctx, client.Registration{HostID: "office", TransportMode: Mode, TransportData: hostID.TransportData()},
			func(ctx context.Context, s *client.Session) {
				sessions <- s
				<-ctx.Done()
			})
	}()
	t.Cleanup(func() {
		cancel()
		<-served
	})
	for deadline := time.Now().Add(10 * time.Second); len(w.Broker.Snapshot().Hosts) == 0; {
		if time.Now().After(deadline) {
			t.Fatal("host not registered")
		}
		if !pause(ctx, 5*time.Millisecond) {
			t.Fatal("canceled")
		}
	}
	dialC := w.Client(w.NATHost(nattest.FullCone()), nil)
	ds, err := dialC.Open(ctx, client.OpenRequest{HostID: "office", TransportMode: Mode, TransportData: dialID.TransportData()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ds.Close() })
	var hs *client.Session
	select {
	case hs = <-sessions:
	case <-time.After(10 * time.Second):
		t.Fatal("no session on the host")
	}
	type accepted struct {
		c   *Conn
		err error
	}
	acc := make(chan accepted, 1)
	go func() {
		c, err := Accept(ctx, hs, hostID)
		acc <- accepted{c, err}
	}()
	dial, err = Dial(ctx, ds, dialID)
	a := <-acc
	if err != nil || a.err != nil {
		t.Fatalf("dial %v, accept %v", err, a.err)
	}
	t.Cleanup(func() {
		_ = dial.Close()
		_ = a.c.Close()
	})
	return a.c, dial
}

// TestOpenStreamUnanswered: a stream the host never answers marks the
// connection as dead (unanswered), a stream the host's stream limit does
// not grant yet does not; and the end of ctx ends the wait for either.
func TestOpenStreamUnanswered(t *testing.T) {
	_, dial := quicPair(t)
	open := func() (unanswered bool, d time.Duration, err error) {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, unanswered, err = dial.openStream(ctx, "")
		return unanswered, time.Since(start), err
	}
	if unanswered, d, err := open(); !unanswered || !errors.Is(err, context.DeadlineExceeded) || d > 5*time.Second {
		t.Fatalf("no answer: unanswered %v, %v after %v", unanswered, err, d)
	}
	for i := 0; ; i++ {
		if _, err := dial.qc.OpenStream(); err != nil {
			break
		}
		if i > 1<<16 {
			t.Fatal("no stream limit")
		}
	}
	if unanswered, d, err := open(); unanswered || !errors.Is(err, context.DeadlineExceeded) || d > 5*time.Second {
		t.Fatalf("stream limit: unanswered %v, %v after %v", unanswered, err, d)
	}
}
