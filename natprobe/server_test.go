package natprobe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/leak"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/protocol"
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
	// stale holds the seqs of the probes of finished exchanges: their
	// replies that come late are dropped by every read.
	stale map[uint32]bool
}

func newUDPClient(t *testing.T, token protocol.Token, route protocol.RouteID) *udpClient {
	t.Helper()
	conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(lo4, 0)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &udpClient{client: newClient(t, token, route, udpwire.RoleInitiator), conn: conn, stale: map[uint32]bool{}}
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

// recv reads replies until n arrived or timeout. Replies that must come are
// waited for by exchange, or by recv in a retry attempt; a fixed timeout
// only bounds a check that nothing arrives.
func (c *udpClient) recv(n int, timeout time.Duration) []reply {
	c.t.Helper()
	var out []reply
	deadline := time.Now().Add(timeout)
	for len(out) < n {
		r, err := c.read(deadline)
		if err != nil {
			break
		}
		out = append(out, r)
	}
	return out
}

// read returns the next reply, skipping the late replies to finished
// exchanges, or the error that ended the read: os.ErrDeadlineExceeded once
// deadline has passed.
func (c *udpClient) read(deadline time.Time) (reply, error) {
	c.t.Helper()
	buf := make([]byte, 2048)
	_ = c.conn.SetReadDeadline(deadline)
	defer func() { _ = c.conn.SetReadDeadline(time.Time{}) }()
	for {
		m, from, err := c.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return reply{}, err
		}
		h, tl, ok := c.open(buf[:m])
		if !ok {
			c.t.Fatalf("undecodable reply from %v", from)
		}
		if !c.stale[h.EchoSeq] {
			return reply{h: h, tl: tl, from: netip.AddrPortFrom(from.Addr().Unmap(), from.Port())}, nil
		}
	}
}

// Loopback can drop a datagram on a loaded machine, so exchange sends its
// probe again every retransmitEvery, for at most exchangeBound: one
// exchange stays within the default rate and probe budget of a session, and
// a test that makes several uses a session for each. retry gives a test
// that cannot send a probe again the same bound, split into attempts whose
// waits double from firstAttemptWait.
const (
	retransmitEvery  = 400 * time.Millisecond
	exchangeBound    = 30 * time.Second
	firstAttemptWait = time.Second
)

// exchange sends a probe built from o to `to` and returns the n replies to
// one transmission of it. Until one transmission has them all, it sends the
// probe again every retransmitEvery, each time with a fresh seq (the server
// refuses a replayed one), for at most exchangeBound or a shorter waitBound,
// and then returns the most replies one transmission got. Replies are
// grouped by the seq they echo, so a reply to another transmission is never
// counted with them, nor by a later read when it comes late; a reply to a
// probe the exchange did not send fails the test. Each transmission is a
// probe to the server, counted in its stats, rate and budget: tests that
// count those exactly or test a limit send once in retry attempts, and a
// check that no reply comes uses send and recv.
func (c *udpClient) exchange(to netip.AddrPort, o probeOpts, n int) []reply {
	c.t.Helper()
	if o.seq != 0 {
		c.t.Fatal("exchange: every transmission needs a fresh seq")
	}
	end := time.Now().Add(min(waitBound(c.t), exchangeBound))
	var sent []uint32
	defer func() {
		for _, seq := range sent {
			c.stale[seq] = true
		}
	}()
	got := map[uint32][]reply{}
	var best []reply
	for {
		o.seq = c.codec.NextSeq()
		sent = append(sent, o.seq)
		c.send(to, o)
		next := time.Now().Add(retransmitEvery)
		if next.After(end) {
			next = end
		}
		for {
			r, err := c.read(next)
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			if err != nil {
				c.t.Fatalf("exchange: %v", err)
			}
			seq := r.h.EchoSeq
			if !slices.Contains(sent, seq) {
				c.t.Fatalf("exchange: reply %+v from %v to probe %d, which it did not send", r.h, r.from, seq)
			}
			got[seq] = append(got[seq], r)
			if len(got[seq]) > len(best) {
				best = got[seq]
			}
			if len(best) == n {
				return best
			}
		}
		if !time.Now().Before(end) {
			return best
		}
	}
}

// retry runs attempt until it reports that every reply it waited for
// arrived, for at most exchangeBound or a shorter waitBound, and fails the
// test when no attempt did. It is for the tests that count the server's
// probes, replies or quotas exactly and so cannot send a probe again: an
// attempt starts its own server and client, sends each probe once and waits
// at most wait for the replies, so a datagram lost on loopback costs an
// attempt instead of the test. Only a missing reply may cost an attempt: a
// count past the exact one fails the test even when replies are missing, as
// another attempt must not hide it, and an attempt closes its server before
// it reports false. Every attempt waits twice as long as the one before, so
// a slow machine still gets its time.
func retry(t *testing.T, attempt func(wait time.Duration) bool) {
	t.Helper()
	bound := min(waitBound(t), exchangeBound)
	end := time.Now().Add(bound)
	for wait := firstAttemptWait; ; wait *= 2 {
		if attempt(min(wait, time.Until(end))) {
			return
		}
		if !time.Now().Before(end) {
			t.Fatalf("no attempt got all its replies within %v", bound)
		}
	}
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
		"table":            {Registry: reg, Groups: loGroup(), SourceTableSize: 3},
		"table too large":  {Registry: reg, Groups: loGroup(), SourceTableSize: math.MaxInt}, // validated, never preallocated
		"invalid bind":     {Registry: reg, Groups: []ObserverGroup{{}}},
		"mapped bind":      {Registry: reg, Groups: []ObserverGroup{{Bind: netip.MustParseAddr("::ffff:127.0.0.1")}}},
		"zoned bind":       {Registry: reg, Groups: []ObserverGroup{{Bind: netip.MustParseAddr("fe80::1%lo0")}}},
		"family mismatch":  {Registry: reg, Groups: []ObserverGroup{{Bind: lo4, Advertise: []netip.Addr{v6}}}},
		"unspecified adv":  {Registry: reg, Groups: []ObserverGroup{{Bind: lo4, Advertise: []netip.Addr{netip.IPv4Unspecified()}}}},
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
	groups := []ObserverGroup{{Bind: netip.IPv4Unspecified(), Advertise: []netip.Addr{netip.MustParseAddr("198.51.100.1")}}, {Bind: v6}}
	s, err := NewServer(ServerConfig{Registry: reg, Groups: groups, SourceRate: Rate{PerSec: 100}})
	if err != nil {
		t.Fatal(err)
	}
	if s.cfg.PortCount != 3 || s.cfg.ExtraSockets != 4 || s.cfg.ReadersPerListener != 2 || s.cfg.SourceRate != (Rate{100, 200}) ||
		len(s.cfg.Groups[1].Advertise) != 1 || s.cfg.Groups[1].Advertise[0] != v6 || len(groups[1].Advertise) != 0 {
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
// address), the extra from the pool, observers, stats, close. The stats
// count each probe exactly, so a lost datagram costs a retry attempt.
func TestServerLoopback(t *testing.T) {
	retry(t, func(wait time.Duration) bool { return loopbackAttempt(t, wait) })
}

func loopbackAttempt(t *testing.T, wait time.Duration) bool {
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
	reps := c.recv(6, wait)
	if len(reps) != 6 {
		st := s.Stats()
		if st.Acks > 3 || st.Extras > 3 || st.PacketsIn > 3 {
			t.Fatalf("%d of 6 replies, stats %+v", len(reps), st)
		}
		t.Logf("%d of 6 replies within %v; stats %+v", len(reps), wait, st)
		_ = s.Close()
		return false
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
	// six before the last count lands. The counts only grow: one past 3
	// fails at once, without waiting for the other.
	deadline := time.Now().Add(waitBound(t))
	for st := s.Stats(); min(st.Acks, st.Extras) < 3 && max(st.Acks, st.Extras) <= 3 && time.Now().Before(deadline); st = s.Stats() {
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
	return true
}

// ProbeSpec lists the live observers of both families with the server's
// extra-reply setting and the second-socket probe.
func TestServerProbeSpec(t *testing.T) {
	for _, noExtra := range []bool{false, true} {
		reg := NewRegistry(RegistryConfig{})
		s, err := NewServer(ServerConfig{Registry: reg, Groups: loGroup(), NoExtraReply: noExtra})
		if err != nil {
			t.Fatal(err)
		}
		if spec := s.ProbeSpec(); spec.Observers != nil || spec.V != protocol.ProbeSpecVersion {
			t.Fatalf("before Start: %+v", spec)
		}
		if err := s.Start(); err != nil {
			t.Fatal(err)
		}
		spec := s.ProbeSpec()
		want := s.Observers(protocol.FamilyUDP4)
		if !slices.Equal(spec.Observers, want) || len(want) != 3 {
			t.Fatalf("observers %+v, want %+v", spec.Observers, want)
		}
		if spec.V != protocol.ProbeSpecVersion || spec.ExtraReply == noExtra || !spec.SecondSocket || spec.STUN != nil {
			t.Fatalf("NoExtraReply=%v: spec %+v", noExtra, spec)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if spec := s.ProbeSpec(); spec.Observers != nil {
			t.Fatalf("after Close: %+v", spec.Observers)
		}
	}
	var nilS *Server
	if spec := nilS.ProbeSpec(); spec.Observers != nil || spec.V != protocol.ProbeSpecVersion {
		t.Fatalf("nil server: %+v", spec)
	}
}

// specObservers keeps a dual-stack server's observers within the protocol's
// 16: at least 8 of each family that has them, each family's first main
// group and alt observer first.
func TestSpecObservers(t *testing.T) {
	// groups returns the observers of main groups first..first+n-1 with
	// ports observers each, then an alt group's, as Server.Observers lists
	// them (by id).
	groups := func(v6 bool, first, n, ports int, alt bool) []protocol.ObserverSpec {
		var out []protocol.ObserverSpec
		add := func(g, p int, isAlt bool) {
			ip := netip.AddrFrom4([4]byte{198, 51, 100, byte(g)})
			if v6 {
				ip = netip.MustParseAddr(fmt.Sprintf("2001:db8::%d", g))
			}
			out = append(out, protocol.ObserverSpec{ID: uint8(g*8 + p), Addr: netip.AddrPortFrom(ip, uint16(3478+p)), Group: uint8(g), Alt: isAlt})
		}
		for g := first; g < first+n; g++ {
			for p := range ports {
				add(g, p, false)
			}
		}
		if alt {
			add(first+n, 0, true)
		}
		return out
	}
	count := func(obs []protocol.ObserverSpec, keep func(protocol.ObserverSpec) bool) int {
		n := 0
		for _, o := range obs {
			if keep(o) {
				n++
			}
		}
		return n
	}
	for _, c := range []struct {
		name   string
		v4, v6 []protocol.ObserverSpec
		n4, n6 int
	}{
		{"within the limit", groups(false, 0, 3, 3, false), groups(true, 3, 1, 3, false), 9, 3},
		{"one family of 16", groups(false, 0, 5, 3, true), nil, 16, 0},
		{"both over 8", groups(false, 0, 3, 3, true), groups(true, 4, 3, 3, true), 8, 8},
		{"one family short", groups(false, 0, 4, 3, true), groups(true, 5, 1, 3, false), 13, 3},
		{"short of 8", groups(false, 0, 2, 3, false), groups(true, 2, 4, 3, true), 6, 10},
	} {
		got := specObservers(c.v4, c.v6)
		is4 := func(o protocol.ObserverSpec) bool { return o.Addr.Addr().Is4() }
		if n4, n6 := count(got, is4), len(got)-count(got, is4); n4 != c.n4 || n6 != c.n6 || len(got) > maxSpecObservers {
			t.Fatalf("%s: %d v4 + %d v6, want %d + %d", c.name, n4, n6, c.n4, c.n6)
		}
		for _, fam := range [][]protocol.ObserverSpec{c.v4, c.v6} {
			var kept []protocol.ObserverSpec
			for _, o := range got {
				if len(fam) > 0 && o.Addr.Addr().Is4() == fam[0].Addr.Addr().Is4() {
					kept = append(kept, o)
				}
			}
			if !slices.IsSortedFunc(kept, func(a, b protocol.ObserverSpec) int { return int(a.ID) - int(b.ID) }) {
				t.Fatalf("%s: not in id order: %+v", c.name, kept)
			}
			if len(kept) == len(fam) || len(kept) == 0 {
				continue
			}
			// Trimmed: the first main group and the alt observer stay.
			first := fam[0].Group
			if count(kept, func(o protocol.ObserverSpec) bool { return !o.Alt && o.Group == first }) !=
				count(fam, func(o protocol.ObserverSpec) bool { return !o.Alt && o.Group == first }) {
				t.Fatalf("%s: first group trimmed: %+v", c.name, kept)
			}
			if count(fam, func(o protocol.ObserverSpec) bool { return o.Alt }) != count(kept, func(o protocol.ObserverSpec) bool { return o.Alt }) {
				t.Fatalf("%s: alt observer dropped: %+v", c.name, kept)
			}
		}
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
	deadline := time.Now().Add(waitBound(t))
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
	if reps := c.exchange(obs[1].Addr, probeOpts{obs: 2}, 1); len(reps) != 1 {
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
	// Every transmission of the exchange may draw an extra.
	reg := NewRegistry(RegistryConfig{ExtraQuotaPerRole: math.MaxUint8})
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
	reps := c.exchange(observerAddr(t, s, 0), probeOpts{obs: 0, extra: true}, 2)
	if len(reps) != 2 {
		t.Fatalf("%d replies", len(reps))
	}
	if reps[0].h.Type == reps[1].h.Type {
		t.Fatalf("two replies of type %d", reps[0].h.Type)
	}
	for _, r := range reps {
		if r.h.Type != udpwire.TProbeAck && r.h.Type != udpwire.TProbeExtra {
			t.Fatalf("reply %+v from %v", r.h, r.from)
		}
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
	deadline := time.Now().Add(waitBound(t))
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
// 127.0.0.1; the advertised address stays 127.0.0.2. The stats count the
// probe, its ack and its alt reply exactly, so a lost datagram costs a retry
// attempt.
func TestServerAltGroup(t *testing.T) {
	retry(t, func(wait time.Duration) bool { return altGroupAttempt(t, wait) })
}

func altGroupAttempt(t *testing.T, wait time.Duration) bool {
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
	reps := c.recv(2, wait)
	if len(reps) != 2 {
		st := s.Stats()
		if st.Acks > 1 || st.Alts > 1 || st.PacketsIn > 1 {
			t.Fatalf("%d of 2 replies, stats %+v", len(reps), st)
		}
		t.Logf("%d of 2 replies within %v; stats %+v", len(reps), wait, st)
		_ = s.Close()
		return false
	}
	if reps[0].h.Type == reps[1].h.Type {
		t.Fatalf("two replies of type %d", reps[0].h.Type)
	}
	for _, r := range reps {
		switch r.h.Type {
		case udpwire.TProbeAck:
			if !r.h.FB {
				t.Fatal("the ack does not declare the alt reply")
			}
		case udpwire.TProbeAlt:
			mu.Lock()
			ok := slices.Contains(altPorts, r.from.Port())
			mu.Unlock()
			if !ok {
				t.Fatalf("alt from %v, not from the alt pool", r.from)
			}
		default:
			t.Fatalf("reply %+v from %v", r.h, r.from)
		}
	}
	// counted after the write returns (see TestServerLoopback); the ack is
	// counted before the alt is sent
	deadline := time.Now().Add(waitBound(t))
	for s.Stats().Alts < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if st := s.Stats(); st.Alts != 1 || st.Acks != 1 || st.PacketsIn != 1 {
		t.Fatalf("stats %+v", st)
	}
	return true
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
	for i, o := range s.Observers(protocol.FamilyUDP4) {
		// A session for each exchange: the retransmissions of one never
		// eat into the probe budget of another.
		id := byte(i + 1)
		register(t, reg, fmt.Sprint("s", id), tok(id), rt(id))
		c := newUDPClient(t, tok(id), rt(id))
		reps := c.exchange(o.Addr, probeOpts{obs: o.ID}, 1)
		if len(reps) != 1 || reps[0].from != o.Addr {
			t.Fatalf("observer %v answered from %v", o.Addr, reps)
		}
	}
}

func TestServerWildcard(t *testing.T) {
	reg := NewRegistry(RegistryConfig{})
	s := startServer(t, ServerConfig{Registry: reg, Groups: []ObserverGroup{{Bind: netip.IPv4Unspecified(), Advertise: []netip.Addr{lo4}}}})
	register(t, reg, "s1", tok(1), rt(1))
	c := newUDPClient(t, tok(1), rt(1))
	o := s.Observers(protocol.FamilyUDP4)[0]
	if reps := c.exchange(o.Addr, probeOpts{obs: 0}, 1); len(reps) != 1 {
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
	wild4 := ObserverGroup{Bind: netip.IPv4Unspecified(), Advertise: []netip.Addr{netip.MustParseAddr("198.51.100.1")}}
	wild6 := ObserverGroup{Bind: netip.IPv6Unspecified(), Advertise: []netip.Addr{netip.MustParseAddr("2001:db8::1")}}
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

// unknownLocalConn hides its local address, as an injected conn may.
type unknownLocalConn struct{ net.PacketConn }

func (unknownLocalConn) LocalAddr() net.Addr { return fakeAddr("somewhere") }

// A listener on a kernel-chosen port whose conn does not tell the port
// cannot be advertised: Start fails and closes what it opened. With an
// explicit BasePort the configured port is advertised.
func TestUnknownListenerPort(t *testing.T) {
	var opened, closed atomic.Int32
	listen := func(network string, laddr netip.AddrPort) (net.PacketConn, error) {
		c, err := defaultListen(network, laddr)
		if err != nil {
			return nil, err
		}
		opened.Add(1)
		return unknownLocalConn{&closeCounter{PacketConn: c, n: &closed}}, nil
	}
	s, err := NewServer(ServerConfig{Registry: NewRegistry(RegistryConfig{}), Groups: loGroup(), Listen: listen})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err == nil || !strings.Contains(err.Error(), "unknown local port") {
		t.Fatalf("Start = %v", err)
	}
	if opened.Load() == 0 || closed.Load() != opened.Load() {
		t.Fatalf("opened %d closed %d", opened.Load(), closed.Load())
	}

	hold, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(lo4, 0)))
	if err != nil {
		t.Fatal(err)
	}
	base := hold.LocalAddr().(*net.UDPAddr).Port
	_ = hold.Close()
	if base+2 > 65535 {
		t.Skip("no room for three ports above", base)
	}
	s2, err := NewServer(ServerConfig{Registry: NewRegistry(RegistryConfig{}), Groups: loGroup(), Listen: listen, BasePort: base})
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.Start(); err != nil {
		t.Skip("ports above", base, "taken meanwhile:", err)
	}
	defer func() { _ = s2.Close() }()
	for i, o := range s2.Observers(protocol.FamilyUDP4) {
		if int(o.Addr.Port()) != base+i {
			t.Fatalf("observer %d advertised at %v, want port %d", i, o.Addr, base+i)
		}
	}
}

// The turn of the extra-reply pool stays in range when its counter passes
// 2^31 and wraps (int is 32 bits on some platforms).
func TestPoolPickWraps(t *testing.T) {
	p := &pool{conns: []packetConn{discardConn{}, discardConn{}, discardConn{}}, ports: []uint16{1, 2, 3}}
	for _, start := range []uint32{1<<31 - 2, math.MaxUint32 - 2} {
		p.next.Store(start)
		for range 6 {
			if _, _, port := p.pick(); port < 1 || port > 3 {
				t.Fatalf("port %d after %d", port, start)
			}
		}
	}
}
