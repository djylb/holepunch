package quicpath

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/djylb/holepunch"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

func TestPeerPin(t *testing.T) {
	id, err := NewIdentity("x")
	if err != nil {
		t.Fatal(err)
	}
	if pin, err := PeerPin(id.TransportData()); err != nil || pin != id.pin {
		t.Fatalf("%q %v", pin, err)
	}
	colons := pinPrefix + strings.ToUpper(id.pin[:2]) + ":" + id.pin[2:]
	if pin, err := PeerPin([]byte(colons)); err != nil || pin != id.pin {
		t.Fatalf("%q: %q %v", colons, pin, err)
	}
	for _, bad := range []string{"", id.pin, "sha256:", "sha256:zz", "sha256:" + id.pin[:62], "md5:" + id.pin} {
		if _, err := PeerPin([]byte(bad)); !errors.Is(err, ErrNoPin) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if _, err := NewIdentity(""); err == nil {
		t.Fatal("identity without an application protocol")
	}
}

// TestTLSConfig: each role gets its side's configuration, and a session
// without the peer's pin or role gets none.
func TestTLSConfig(t *testing.T) {
	id, err := NewIdentity("x")
	if err != nil {
		t.Fatal(err)
	}
	peer := id.TransportData()
	c, err := id.TLSConfig(holepunch.Result{Role: protocol.RoleInitiator, PeerTransportData: peer})
	if err != nil || !c.InsecureSkipVerify || c.ServerName != "x" || c.VerifyConnection == nil {
		t.Fatalf("initiator %+v %v", c, err)
	}
	s, err := id.TLSConfig(holepunch.Result{Role: protocol.RoleResponder, PeerTransportData: peer})
	if err != nil || s.ClientAuth != tls.RequireAnyClientCert || !s.SessionTicketsDisabled || s.VerifyConnection == nil {
		t.Fatalf("responder %+v %v", s, err)
	}
	if _, err := id.TLSConfig(holepunch.Result{Role: protocol.RoleInitiator}); !errors.Is(err, ErrNoPin) {
		t.Fatalf("no pin: %v", err)
	}
	if _, err := id.TLSConfig(holepunch.Result{Role: protocol.RoleServer, PeerTransportData: peer}); !errors.Is(err, ErrRole) {
		t.Fatalf("server role: %v", err)
	}
}

// TestIdentityTLS: each side accepts only the pinned peer, and no
// connection can be resumed: the responder issues no session ticket, so a
// client with a session cache still makes a full handshake, pin check
// included, every time.
func TestIdentityTLS(t *testing.T) {
	responder, initiator, impostor := mustIdentity(t), mustIdentity(t), mustIdentity(t)
	n := nattest.NewNetwork()
	defer func() { _ = n.Close() }()
	type outcome struct {
		state                tls.ConnectionState
		clientErr, serverErr error
	}
	handshake := func(server, client *tls.Config) outcome {
		// TLS needs buffered streams: over net.Pipe the client's change
		// cipher spec and the server's first flight would wait for each
		// other.
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
				// A byte after the handshake: the client reads it, and with
				// it any session ticket the server sent first.
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

	server := responder.serverTLS(initiator.pin)
	cache := tls.NewLRUClientSessionCache(4)
	for range 2 {
		cfg := initiator.clientTLS(responder.pin)
		cfg.ClientSessionCache = cache
		o := handshake(server, cfg)
		if o.clientErr != nil || o.serverErr != nil || o.state.DidResume {
			t.Fatalf("pinned peers: client %v, server %v, resumed %v", o.clientErr, o.serverErr, o.state.DidResume)
		}
	}
	if o := handshake(impostor.serverTLS(initiator.pin), initiator.clientTLS(responder.pin)); !errors.Is(o.clientErr, ErrPin) {
		t.Fatalf("initiator and an impostor responder: %v", o.clientErr)
	}
	if o := handshake(server, impostor.clientTLS(responder.pin)); o.serverErr == nil {
		t.Fatal("responder accepted an impostor initiator")
	}
	if err := verifyPin(responder.pin)(tls.ConnectionState{}); !errors.Is(err, ErrPin) {
		t.Fatal("no certificate accepted")
	}
}

func mustIdentity(t *testing.T) *Identity {
	t.Helper()
	id, err := NewIdentity("x")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestPathConfig(t *testing.T) {
	c := pathConfig(nil, holepunch.Path{}, defaultTransportTimeout)
	if c.HandshakeIdleTimeout != defaultTransportTimeout || c.MaxIdleTimeout != defaultIdleTimeout || c.KeepAlivePeriod != defaultIdleTimeout/3 {
		t.Fatalf("defaults %+v", c)
	}
	advice := holepunch.Path{Keepalive: holepunch.KeepaliveAdvice{Interval: 10 * time.Second, Timeout: 30 * time.Second}}
	c = pathConfig(nil, advice, 3*time.Second)
	if c.HandshakeIdleTimeout != 3*time.Second || c.MaxIdleTimeout != 30*time.Second || c.KeepAlivePeriod != 10*time.Second {
		t.Fatalf("advice %+v", c)
	}
	base := &quic.Config{
		MaxIdleTimeout: 6 * time.Second, MaxIncomingStreams: 7,
		GetConfigForClient: func(*quic.ClientInfo) (*quic.Config, error) { return nil, nil },
	}
	c = pathConfig(base, advice, 3*time.Second)
	if c.MaxIdleTimeout != 6*time.Second || c.KeepAlivePeriod != 2*time.Second || c.MaxIncomingStreams != 7 || c.GetConfigForClient != nil {
		t.Fatalf("caller's %+v", c)
	}
	if base.KeepAlivePeriod != 0 || base.GetConfigForClient == nil {
		t.Fatal("caller's configuration modified")
	}
}

// TestListenConfig: the responder's listener gives each peer address its
// path's configuration and refuses every other address before the
// handshake; the caller's GetConfigForClient picks the base.
func TestListenConfig(t *testing.T) {
	var pc net.PacketConn = &net.UDPConn{}
	lan := holepunch.Path{Conn: pc, Kind: protocol.PathLAN, RemoteAddr: netip.MustParseAddrPort("192.168.1.7:4000"),
		Keepalive: holepunch.KeepaliveAdvice{Interval: 25 * time.Second, Timeout: 75 * time.Second}}
	public := holepunch.Path{Conn: pc, Kind: protocol.PathPublic, RemoteAddr: netip.MustParseAddrPort("203.0.113.7:4000"),
		Keepalive: holepunch.KeepaliveAdvice{Interval: 10 * time.Second, Timeout: 30 * time.Second}}
	s := &socket{pc: pc}
	refuse := errors.New("refused by the caller")
	e := &Endpoint{
		paths: []holepunch.Path{public, lan}, pathOf: []*socket{s, s}, timeout: time.Second,
		quic: &quic.Config{GetConfigForClient: func(info *quic.ClientInfo) (*quic.Config, error) {
			if info.RemoteAddr.(*net.UDPAddr).Port == 1 {
				return nil, refuse
			}
			return &quic.Config{MaxIncomingStreams: 9}, nil
		}},
	}
	get := e.listenConfig(s, public).GetConfigForClient
	for addr, want := range map[string]time.Duration{"203.0.113.7:4000": 30 * time.Second, "[::ffff:192.168.1.7]:4000": 75 * time.Second} {
		c, err := get(&quic.ClientInfo{RemoteAddr: net.UDPAddrFromAddrPort(netip.MustParseAddrPort(addr))})
		if err != nil || c.MaxIdleTimeout != want || c.MaxIncomingStreams != 9 {
			t.Fatalf("%s: %+v %v", addr, c, err)
		}
	}
	for addr, want := range map[string]error{"203.0.113.7:4001": errUnexpectedPeer, "203.0.113.8:4000": errUnexpectedPeer} {
		if _, err := get(&quic.ClientInfo{RemoteAddr: net.UDPAddrFromAddrPort(netip.MustParseAddrPort(addr))}); !errors.Is(err, want) {
			t.Fatalf("%s: %v", addr, err)
		}
	}
	e.paths[0].RemoteAddr = netip.MustParseAddrPort("203.0.113.7:1")
	if _, err := get(&quic.ClientInfo{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 1}}); !errors.Is(err, refuse) {
		t.Fatalf("caller's refusal: %v", err)
	}
}

func TestAddrPort(t *testing.T) {
	want := netip.MustParseAddrPort("203.0.113.7:4000")
	for a, ok := range map[net.Addr]bool{
		&net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4000}:        true,
		&net.UDPAddr{IP: net.ParseIP("::ffff:203.0.113.7"), Port: 4000}: true,
		&net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4000}:        true,
		&net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4001}:        false,
		&net.UnixAddr{Name: "x", Net: "unix"}:                           false,
	} {
		if got, _ := addrPort(a); (got == want) != ok {
			t.Errorf("%v: %v", a, got)
		}
	}
	var nilUDP *net.UDPAddr
	for _, a := range []net.Addr{nil, nilUDP} {
		if _, ok := addrPort(a); ok {
			t.Errorf("%#v accepted", a)
		}
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		cause error
		want  error
	}{
		{nil, ErrClosed},
		{&quic.IdleTimeoutError{}, ErrIdleTimeout},
		{&quic.ApplicationError{ErrorCode: codeClosed}, ErrClosed},
		{fmt.Errorf("wrapped: %w", quic.ErrTransportClosed), ErrClosed},
		{&quic.ApplicationError{ErrorCode: codeClosed, Remote: true}, ErrPeerClosed},
		{&quic.TransportError{ErrorCode: quic.InternalError, Remote: true}, ErrPeerClosed},
		{&quic.StatelessResetError{}, ErrPeerClosed},
	}
	for _, c := range cases {
		if err := classify(c.cause); !errors.Is(err, c.want) {
			t.Errorf("%v: %v, want %v", c.cause, err, c.want)
		}
	}
	local := &quic.TransportError{ErrorCode: quic.ProtocolViolation}
	if err := classify(local); !errors.Is(err, local) || errors.Is(err, ErrClosed) || errors.Is(err, ErrPeerClosed) {
		t.Fatalf("local transport error: %v", err)
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
