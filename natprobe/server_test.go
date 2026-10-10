package natprobe

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/leak"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/udpwire"
)

var lo4 = netip.MustParseAddr("127.0.0.1")

func loGroup() []ObserverGroup { return []ObserverGroup{{Bind: lo4}} }

func startServer(t *testing.T, cfg ServerConfig) *Server {
	t.Helper()
	if cfg.Registry == nil {
		cfg.Registry = NewRegistry(RegistryConfig{})
	}
	if cfg.Groups == nil {
		cfg.Groups = loGroup()
	}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// udpClient is a real loopback client socket.
type udpClient struct {
	*client
	conn *net.UDPConn
}

func newUDPClient(t *testing.T, token protocol.Token, route protocol.RouteID) *udpClient {
	t.Helper()
	conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(lo4, 0)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &udpClient{client: newClient(t, token, route, udpwire.RoleInitiator), conn: conn}
}

func (c *udpClient) local() netip.AddrPort { return c.conn.LocalAddr().(*net.UDPAddr).AddrPort() }

func (c *udpClient) send(to netip.AddrPort, o probeOpts) {
	c.t.Helper()
	if _, err := c.conn.WriteToUDPAddrPort(c.probe(o), to); err != nil {
		c.t.Fatal(err)
	}
}

type reply struct {
	h    udpwire.Header
	tl   udpwire.TLVs
	from netip.AddrPort
}

// waitBound is how long a test waits for something that must happen over
// real loopback sockets: until shortly before the test binary's deadline,
// so that a loaded machine — every package's tests in parallel under the
// race detector — slows the test down instead of failing it. Without a
// deadline it is a minute.
func waitBound(t *testing.T) time.Duration {
	d, ok := t.Deadline()
	if !ok {
		return time.Minute
	}
	return max(time.Until(d)*9/10, time.Second)
}

// await reads replies until n arrived, waiting at most waitBound.
func (c *udpClient) await(n int) []reply {
	c.t.Helper()
	return c.recv(n, waitBound(c.t))
}

// recv reads replies until n arrived or timeout: a positive wait uses
// await; a fixed timeout only bounds a check that nothing arrives.
func (c *udpClient) recv(n int, timeout time.Duration) []reply {
	c.t.Helper()
	var out []reply
	buf := make([]byte, 2048)
	_ = c.conn.SetReadDeadline(time.Now().Add(timeout))
	defer func() { _ = c.conn.SetReadDeadline(time.Time{}) }()
	for len(out) < n {
		m, from, err := c.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			break
		}
		h, tl, ok := c.open(buf[:m])
		if !ok {
			c.t.Fatalf("undecodable reply from %v", from)
		}
		out = append(out, reply{h: h, tl: tl, from: netip.AddrPortFrom(from.Addr().Unmap(), from.Port())})
	}
	return out
}

func observerAddr(t *testing.T, s *Server, id uint8) netip.AddrPort {
	t.Helper()
	for _, o := range s.Observers(protocol.FamilyUDP4) {
		if o.ID == id {
			return o.Addr
		}
	}
	t.Fatalf("no observer %d", id)
	return netip.AddrPort{}
}

func TestNewServerValidation(t *testing.T) {
	reg := NewRegistry(RegistryConfig{})
	v6 := netip.MustParseAddr("::1")
	cases := map[string]ServerConfig{
		"no registry":      {Groups: loGroup()},
		"no groups":        {Registry: reg},
		"port count":       {Registry: reg, Groups: loGroup(), PortCount: 9},
		"port count low":   {Registry: reg, Groups: loGroup(), PortCount: 1},
		"base port":        {Registry: reg, Groups: loGroup(), BasePort: 65534},
		"negative port":    {Registry: reg, Groups: loGroup(), BasePort: -1},
		"extra sockets":    {Registry: reg, Groups: loGroup(), ExtraSockets: 17},
		"readers":          {Registry: reg, Groups: loGroup(), ReadersPerListener: 9},
		"sweep":            {Registry: reg, Groups: loGroup(), SweepInterval: -1},
		"table":            {Registry: reg, Groups: loGroup(), SourceTableSize: 3},
		"table too large":  {Registry: reg, Groups: loGroup(), SourceTableSize: math.MaxInt}, // validated, never preallocated
		"invalid bind":     {Registry: reg, Groups: []ObserverGroup{{}}},
		"mapped bind":      {Registry: reg, Groups: []ObserverGroup{{Bind: netip.MustParseAddr("::ffff:127.0.0.1")}}},
		"zoned bind":       {Registry: reg, Groups: []ObserverGroup{{Bind: netip.MustParseAddr("fe80::1%lo0")}}},
		"wildcard no adv":  {Registry: reg, Groups: []ObserverGroup{{Bind: netip.IPv4Unspecified()}}},
		"family mismatch":  {Registry: reg, Groups: []ObserverGroup{{Bind: lo4, Advertise: v6}}},
		"unspecified adv":  {Registry: reg, Groups: []ObserverGroup{{Bind: lo4, Advertise: netip.IPv4Unspecified()}}},
		"only alt":         {Registry: reg, Groups: []ObserverGroup{{Bind: lo4, Alt: true}}},
		"two alt":          {Registry: reg, Groups: []ObserverGroup{{Bind: lo4}, {Bind: lo4, Alt: true}, {Bind: lo4, Alt: true}}},
		"too many v4 obs":  {Registry: reg, Groups: []ObserverGroup{{Bind: lo4}, {Bind: lo4}, {Bind: lo4}}, PortCount: 8},
		"too many groups":  {Registry: reg, Groups: make([]ObserverGroup, 33)},
		"multicast bind":   {Registry: reg, Groups: []ObserverGroup{{Bind: netip.MustParseAddr("224.0.0.1")}}},
		"zero source rate": {Registry: reg, Groups: loGroup(), SourceRate: Rate{Burst: 5}},
	}
	for name, cfg := range cases {
		if _, err := NewServer(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	groups := []ObserverGroup{{Bind: netip.IPv4Unspecified(), Advertise: netip.MustParseAddr("198.51.100.1")}, {Bind: v6}}
	s, err := NewServer(ServerConfig{Registry: reg, Groups: groups, SourceRate: Rate{PerSec: 100}})
	if err != nil {
		t.Fatal(err)
	}
	if s.cfg.PortCount != 3 || s.cfg.ExtraSockets != 4 || s.cfg.ReadersPerListener != 2 || s.cfg.SourceRate != (Rate{100, 200}) ||
		s.cfg.Groups[1].Advertise != v6 || groups[1].Advertise.IsValid() {
		t.Fatalf("defaults %+v (caller's groups %+v)", s.cfg, groups)
	}
	if s2, _ := NewServer(ServerConfig{Registry: reg, Groups: loGroup()}); s2.cfg.SourceRate != (Rate{512, 1024}) {
		t.Fatalf("default source rate %+v", s2.cfg.SourceRate)
	}
	if s.Observers(protocol.FamilyUDP4) != nil {
		t.Fatal("observers before Start")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err == nil || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("start after close: %v", err)
	}
}

// Loopback on the wire: explicit binding (the ack comes from the probed
// address), the extra from the pool, observers, stats, close.
func TestServerLoopback(t *testing.T) {
	reg := NewRegistry(RegistryConfig{})
	s := startServer(t, ServerConfig{Registry: reg})
	obs := s.Observers(protocol.FamilyUDP4)
	if len(obs) != 3 || s.Observers(protocol.FamilyUDP6) != nil {
		t.Fatalf("observers %+v", obs)
	}
	for i, o := range obs {
		if o.ID != uint8(i) || o.Group != 0 || o.Alt || o.Addr.Addr() != lo4 || o.Addr.Port() == 0 {
			t.Fatalf("observer %+v", o)
		}
	}
	register(t, reg, "s1", tok(1), rt(1))
	c := newUDPClient(t, tok(1), rt(1))
	for _, o := range obs {
		c.send(o.Addr, probeOpts{obs: o.ID, extra: true})
	}
	reps := c.await(6)
	if len(reps) != 6 {
		t.Fatalf("%d replies", len(reps))
	}
	acks := map[uint8]reply{}
	for _, r := range reps {
		if r.h.Type == udpwire.TProbeAck {
			acks[uint8(r.h.Aux)] = r
		}
	}
	for _, r := range reps {
		switch r.h.Type {
		case udpwire.TProbeAck:
			if r.from != observerAddr(t, s, uint8(r.h.Aux)) || r.tl.Observed != c.local() || !r.h.FA || r.tl.Cookie == 0 {
				t.Fatalf("ack %+v from %v", r.h, r.from)
			}
		case udpwire.TProbeExtra:
			a := acks[uint8(r.h.Aux)]
			if r.from.Addr() != lo4 || r.from.Port() != a.tl.ExtraPort || r.from == observerAddr(t, s, uint8(r.h.Aux)) {
				t.Fatalf("extra from %v, declared %d", r.from, a.tl.ExtraPort)
			}
		default:
			t.Fatalf("reply %+v from %v", r.h, r.from)
		}
	}
	// A reply is counted after its write returns, so the client can hold all
	// six before the last count lands.
	deadline := time.Now().Add(waitBound(t))
	for st := s.Stats(); (st.Acks != 3 || st.Extras != 3) && time.Now().Before(deadline); st = s.Stats() {
		time.Sleep(time.Millisecond)
	}
	st := s.Stats()
	if st.Acks != 3 || st.Extras != 3 || st.PacketsIn != 3 || st.BytesOut > st.BytesIn || st.Panics != 0 {
		t.Fatalf("stats %+v", st)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil || s.Observers(protocol.FamilyUDP4) != nil {
		t.Fatal("second close / observers after close")
	}
	if err := s.Start(); err == nil {
		t.Fatal("restart after close")
	}
}

// A failure while binding socket N closes every socket opened
// before, the goroutines included; Close afterwards is a no-op.
func TestServerStartFailureCleansUp(t *testing.T) {
	warm, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(lo4, 0)))
	if err != nil {
		t.Fatal(err)
	}
	_ = warm.Close()
	baseline, fdErr := leak.OpenFDs()
	for n := 1; n <= 7; n++ {
		var opened, closed atomic.Int32
		calls := 0
		listen := func(network string, laddr netip.AddrPort) (net.PacketConn, error) {
			calls++
			if calls == n {
				return nil, errors.New("injected bind failure")
			}
			c, err := defaultListen(network, laddr)
			if err != nil {
				return nil, err
			}
			opened.Add(1)
			return &closeCounter{PacketConn: c, n: &closed}, nil
		}
		s, err := NewServer(ServerConfig{Registry: NewRegistry(RegistryConfig{}), Groups: loGroup(), Listen: listen})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Start(); err == nil || !strings.Contains(err.Error(), "injected") {
			t.Fatalf("n=%d: %v", n, err)
		}
		if opened.Load() != int32(n-1) || closed.Load() != opened.Load() {
			t.Fatalf("n=%d: opened %d closed %d", n, opened.Load(), closed.Load())
		}
		if err := s.Close(); err != nil {
			t.Fatalf("close after a failed start: %v", err)
		}
	}
	// a real port conflict
	hold, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(lo4, 0)))
	if err != nil {
		t.Fatal(err)
	}
	port := hold.LocalAddr().(*net.UDPAddr).Port
	s, err := NewServer(ServerConfig{Registry: NewRegistry(RegistryConfig{}), Groups: loGroup(), BasePort: port - 1, PortCount: 2})
	if err == nil {
		err = s.Start()
	}
	_ = hold.Close()
	if err == nil {
		t.Fatal("the port conflict was not reported")
	}
	// a typed-nil and a panicking Listen
	for _, l := range []func(string, netip.AddrPort) (net.PacketConn, error){
		func(string, netip.AddrPort) (net.PacketConn, error) { return (*net.UDPConn)(nil), nil },
		func(string, netip.AddrPort) (net.PacketConn, error) { panic("listen") },
	} {
		s, _ := NewServer(ServerConfig{Registry: NewRegistry(RegistryConfig{}), Groups: loGroup(), Listen: l})
		if err := s.Start(); err == nil {
			t.Fatal("a bad Listen was accepted")
		}
	}
	if fdErr == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := leak.CheckFDs(ctx, baseline); err != nil {
			t.Fatal(err)
		}
	}
}

type closeCounter struct {
	net.PacketConn
	n    *atomic.Int32
	once sync.Once
}

func (c *closeCounter) Close() error {
	c.once.Do(func() { c.n.Add(1) })
	return c.PacketConn.Close()
}

// A reader-loop panic only stops its listener.
func TestServerReaderLoopPanic(t *testing.T) {
	reg := NewRegistry(RegistryConfig{})
	var logs bytes.Buffer
	var logMu sync.Mutex
	calls := 0
	listen := func(network string, laddr netip.AddrPort) (net.PacketConn, error) {
		c, err := defaultListen(network, laddr)
		if err != nil {
			return nil, err
		}
		calls++
		if calls == 2 { // listener id 1
			return &panicReadConn{UDPConn: c.(*net.UDPConn)}, nil
		}
		return c, nil
	}
	logger := slog.New(slog.NewTextHandler(&lockedWriter{w: &logs, mu: &logMu}, nil))
	s := startServer(t, ServerConfig{Registry: reg, Listen: listen, Logger: logger})
	deadline := time.Now().Add(2 * time.Second)
	for s.Stats().DeadListeners == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	st := s.Stats()
	if st.DeadListeners != 1 || st.Panics == 0 {
		t.Fatalf("stats %+v", st)
	}
	obs := s.Observers(protocol.FamilyUDP4)
	if len(obs) != 2 || obs[0].ID != 0 || obs[1].ID != 2 {
		t.Fatalf("observers %+v", obs)
	}
	register(t, reg, "s1", tok(1), rt(1))
	c := newUDPClient(t, tok(1), rt(1))
	c.send(obs[1].Addr, probeOpts{obs: 2})
	if reps := c.await(1); len(reps) != 1 {
		t.Fatal("the surviving listener does not answer")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	logMu.Lock()
	defer logMu.Unlock()
	if out := logs.String(); !strings.Contains(out, "recovered panic") || !strings.Contains(out, "listener stopped") || strings.Contains(out, "goroutine ") {
		t.Fatalf("log %q", out)
	}
}

type lockedWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

type panicReadConn struct{ *net.UDPConn }

func (c *panicReadConn) ReadFromUDPAddrPort([]byte) (int, netip.AddrPort, error) {
	panic("reader loop")
}

// An injected conn without the AddrPort methods is adapted.
func TestServerGenericConn(t *testing.T) {
	reg := NewRegistry(RegistryConfig{})
	listen := func(network string, laddr netip.AddrPort) (net.PacketConn, error) {
		c, err := defaultListen(network, laddr)
		if err != nil {
			return nil, err
		}
		return plainConn{c}, nil
	}
	s := startServer(t, ServerConfig{Registry: reg, Listen: listen, ReadersPerListener: 1, ExtraSockets: 1})
	register(t, reg, "s1", tok(1), rt(1))
	c := newUDPClient(t, tok(1), rt(1))
	c.send(observerAddr(t, s, 0), probeOpts{obs: 0, extra: true})
	if reps := c.await(2); len(reps) != 2 {
		t.Fatalf("%d replies", len(reps))
	}
}

type plainConn struct{ net.PacketConn }

// A conn whose reads keep failing is paused, not spun, and still closes.
func TestServerReadErrors(t *testing.T) {
	var reads atomic.Int64
	listen := func(network string, laddr netip.AddrPort) (net.PacketConn, error) {
		c, err := defaultListen(network, laddr)
		if err != nil {
			return nil, err
		}
		return &failingConn{PacketConn: c, reads: &reads}, nil
	}
	s := startServer(t, ServerConfig{Listen: listen, ReadersPerListener: 1})
	deadline := time.Now().Add(2 * time.Second)
	for s.Stats().ReadErrors < 2*readErrorBurst && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if st := s.Stats(); st.ReadErrors < 2*readErrorBurst {
		t.Fatalf("read errors %d", st.ReadErrors)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

// failingConn fails every read with a temporary error until it is closed.
type failingConn struct {
	net.PacketConn
	reads  *atomic.Int64
	closed atomic.Bool
}

func (c *failingConn) ReadFrom([]byte) (int, net.Addr, error) {
	c.reads.Add(1)
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	return 0, nil, errors.New("temporary")
}

func (c *failingConn) Close() error {
	c.closed.Store(true)
	return c.PacketConn.Close()
}

// The standalone sweeper removes expired entries and stops with Close.
func TestServerSweeper(t *testing.T) {
	reg := NewRegistry(RegistryConfig{})
	s := startServer(t, ServerConfig{Registry: reg, SweepInterval: 10 * time.Millisecond})
	if _, err := reg.Register(Registration{SessionID: "s", Route: rt(1), Token: tok(1), TTL: 20 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for reg.Len() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if reg.Len() != 0 {
		t.Fatal("not swept")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

// Concurrent Close returns one result and leaves nothing behind.
func TestServerCloseConcurrent(t *testing.T) {
	s := startServer(t, ServerConfig{})
	var wg sync.WaitGroup
	errs := make([]error, 100)
	for i := range 100 {
		wg.Go(func() { errs[i] = s.Close() })
	}
	wg.Wait()
	for _, err := range errs {
		if !errors.Is(err, errs[0]) {
			t.Fatalf("different results %v %v", err, errs[0])
		}
	}
	var nilS *Server
	if nilS.Close() != nil || nilS.Start() == nil || nilS.Observers(protocol.FamilyUDP4) != nil || nilS.Stats() != (ServerStats{}) {
		t.Fatal("nil server")
	}
	s2, _ := NewServer(ServerConfig{Registry: NewRegistry(RegistryConfig{}), Groups: loGroup()})
	if err := s2.Close(); err != nil { // never started
		t.Fatal(err)
	}
	s3 := startServer(t, ServerConfig{})
	if err := s3.Start(); err == nil {
		t.Fatal("double start")
	}
	// a close racing a start leaves the server closed
	for range 20 {
		s4, _ := NewServer(ServerConfig{Registry: NewRegistry(RegistryConfig{}), Groups: loGroup()})
		done := make(chan error, 1)
		go func() { done <- s4.Start() }()
		_ = s4.Close()
		if err := <-done; err == nil && s4.Observers(protocol.FamilyUDP4) != nil {
			t.Fatal("observers after close")
		}
		_ = s4.Close()
	}
}

// The alt group: change-IP replies come from the alt pool. 127.0.0.2 is not
// configured on every host, so the alt group's Bind is rewritten to
// 127.0.0.1; the advertised address stays 127.0.0.2.
func TestServerAltGroup(t *testing.T) {
	reg := NewRegistry(RegistryConfig{})
	alt := netip.MustParseAddr("127.0.0.2")
	var altPorts []uint16
	var mu sync.Mutex
	listen := func(network string, laddr netip.AddrPort) (net.PacketConn, error) {
		isAlt := laddr.Addr() == alt
		if isAlt {
			laddr = netip.AddrPortFrom(lo4, laddr.Port())
		}
		c, err := defaultListen(network, laddr)
		if err == nil && isAlt {
			mu.Lock()
			altPorts = append(altPorts, c.LocalAddr().(*net.UDPAddr).AddrPort().Port())
			mu.Unlock()
		}
		return c, err
	}
	s := startServer(t, ServerConfig{Registry: reg, Listen: listen, Groups: []ObserverGroup{{Bind: lo4}, {Bind: alt, Alt: true}}})
	obs := s.Observers(protocol.FamilyUDP4)
	if len(obs) != 4 || !obs[3].Alt || obs[3].ID != 8 || obs[3].Group != 1 || obs[3].Addr.Addr() != alt {
		t.Fatalf("observers %+v", obs)
	}
	register(t, reg, "s1", tok(1), rt(1))
	c := newUDPClient(t, tok(1), rt(1))
	c.send(observerAddr(t, s, 0), probeOpts{obs: 0, alt: true})
	reps := c.await(2)
	if len(reps) != 2 {
		t.Fatalf("%d replies", len(reps))
	}
	for _, r := range reps {
		if r.h.Type == udpwire.TProbeAck && !r.h.FB {
			t.Fatal("the ack does not declare the alt reply")
		}
		if r.h.Type == udpwire.TProbeAlt {
			mu.Lock()
			ok := false
			for _, p := range altPorts {
				ok = ok || p == r.from.Port()
			}
			mu.Unlock()
			if !ok {
				t.Fatalf("alt from %v, not from the alt pool", r.from)
			}
		}
	}
	// counted after the write returns (see TestServerLoopback)
	deadline := time.Now().Add(2 * time.Second)
	for s.Stats().Alts != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if st := s.Stats(); st.Alts != 1 {
		t.Fatalf("stats %+v", st)
	}
}

// With two loopback IPs (Linux; skipped where 127.0.0.2 does not
// exist) each group answers from its own IP.
func TestExplicitBindReplySource(t *testing.T) {
	second := netip.MustParseAddr("127.0.0.2")
	probe, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(second, 0)))
	if err != nil {
		t.Skip("127.0.0.2 not available:", err)
	}
	_ = probe.Close()
	reg := NewRegistry(RegistryConfig{})
	s := startServer(t, ServerConfig{Registry: reg, Groups: []ObserverGroup{{Bind: lo4}, {Bind: second}}})
	register(t, reg, "s1", tok(1), rt(1))
	c := newUDPClient(t, tok(1), rt(1))
	for _, o := range s.Observers(protocol.FamilyUDP4) {
		c.send(o.Addr, probeOpts{obs: o.ID})
		reps := c.await(1)
		if len(reps) != 1 || reps[0].from != o.Addr {
			t.Fatalf("observer %v answered from %v", o.Addr, reps)
		}
	}
}

func TestServerWildcard(t *testing.T) {
	reg := NewRegistry(RegistryConfig{})
	s := startServer(t, ServerConfig{Registry: reg, Groups: []ObserverGroup{{Bind: netip.IPv4Unspecified(), Advertise: lo4}}})
	register(t, reg, "s1", tok(1), rt(1))
	c := newUDPClient(t, tok(1), rt(1))
	o := s.Observers(protocol.FamilyUDP4)[0]
	c.send(o.Addr, probeOpts{obs: 0})
	if reps := c.await(1); len(reps) != 1 {
		t.Fatal("the wildcard listener does not answer")
	}
	t.Logf("wildcard_multi_ip on this host: %v", s.Stats().WildcardMultiIP)
}

func TestWildcardFamilies(t *testing.T) {
	pfx := func(ss ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, s := range ss {
			out = append(out, netip.MustParsePrefix(s))
		}
		return out
	}
	wild4 := ObserverGroup{Bind: netip.IPv4Unspecified(), Advertise: netip.MustParseAddr("198.51.100.1")}
	wild6 := ObserverGroup{Bind: netip.IPv6Unspecified(), Advertise: netip.MustParseAddr("2001:db8::1")}
	explicit := ObserverGroup{Bind: netip.MustParseAddr("198.51.100.1")}
	two4 := pfx("198.51.100.1/24", "203.0.113.7/24", "10.0.0.1/8", "127.0.0.1/8", "2001:db8::1/64")
	if f := wildcardFamilies([]ObserverGroup{wild4, wild4, wild6}, two4); len(f) != 1 || f[0] != protocol.FamilyUDP4 {
		t.Fatalf("families %v", f)
	}
	if f := wildcardFamilies([]ObserverGroup{explicit}, two4); f != nil {
		t.Fatalf("explicit binding flagged: %v", f)
	}
	if f := wildcardFamilies([]ObserverGroup{wild4, wild6}, pfx("198.51.100.1/24", "10.0.0.1/8", "2001:db8::1/64", "2001:db8:1::1/64")); len(f) != 1 || f[0] != protocol.FamilyUDP6 {
		t.Fatalf("families %v", f)
	}
}

// The helpers that adapt net.Addr values.
func TestAddrHelpers(t *testing.T) {
	if a := addrPortOf(nil); a.IsValid() {
		t.Fatal("nil addr")
	}
	if a := addrPortOf((*net.UDPAddr)(nil)); a.IsValid() {
		t.Fatal("nil udp addr")
	}
	if a := addrPortOf(&net.IPAddr{IP: net.IPv4(1, 2, 3, 4)}); a.IsValid() {
		t.Fatalf("ip addr %v", a)
	}
	if a := addrPortOf(fakeAddr("1.2.3.4:5")); a != netip.MustParseAddrPort("1.2.3.4:5") {
		t.Fatalf("string addr %v", a)
	}
	if famIndex(protocol.FamilyUDP6) != 1 || famIndex(protocol.FamilyUDP4) != 0 {
		t.Fatal("family index")
	}
}

type fakeAddr string

func (a fakeAddr) Network() string { return "udp" }
func (a fakeAddr) String() string  { return string(a) }

type panicLocalConn struct{ net.PacketConn }

func (panicLocalConn) LocalAddr() net.Addr { panic("local addr") }

type panicBufferConn struct{ net.PacketConn }

func (panicBufferConn) SetReadBuffer(int) error { panic("read buffer") }

// The methods of an injected conn run inside recover boundaries: a
// panicking LocalAddr or SetReadBuffer is a Start error, never a crash, and
// what was opened is closed.
func TestInjectedConnPanicIsBindFailure(t *testing.T) {
	for name, wrap := range map[string]func(net.PacketConn) net.PacketConn{
		"LocalAddr":     func(c net.PacketConn) net.PacketConn { return panicLocalConn{c} },
		"SetReadBuffer": func(c net.PacketConn) net.PacketConn { return panicBufferConn{c} },
	} {
		var opened, closed atomic.Int32
		listen := func(network string, laddr netip.AddrPort) (net.PacketConn, error) {
			c, err := defaultListen(network, laddr)
			if err != nil {
				return nil, err
			}
			opened.Add(1)
			return wrap(&closeCounter{PacketConn: c, n: &closed}), nil
		}
		s, err := NewServer(ServerConfig{Registry: NewRegistry(RegistryConfig{}), Groups: loGroup(), Listen: listen})
		if err != nil {
			t.Fatal(err)
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s: Start panicked: %v", name, r)
				}
			}()
			if err := s.Start(); err == nil || !strings.Contains(err.Error(), "panic") {
				t.Fatalf("%s: Start = %v", name, err)
			}
		}()
		if err := s.Close(); err != nil {
			t.Fatalf("%s: close: %v", name, err)
		}
		if opened.Load() == 0 || closed.Load() != opened.Load() {
			t.Fatalf("%s: opened %d closed %d", name, opened.Load(), closed.Load())
		}
	}
}
