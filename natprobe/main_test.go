package natprobe

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/goroutines"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/internal/probetest"
	"github.com/djylb/holepunch/internal/testkit"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/protocol"
)

func TestMain(m *testing.M) { goroutines.VerifyTestMain(m) }

func tok(b byte) protocol.Token {
	var t protocol.Token
	for i := range t {
		t[i] = b + byte(i)
	}
	return t
}

func rt(b byte) protocol.RouteID {
	var r protocol.RouteID
	for i := range r {
		r[i] = b ^ byte(i*7+1)
	}
	return r
}

// captured is one datagram written by the server.
type captured struct {
	b    []byte
	from netip.AddrPort
	to   netip.AddrPort
}

// captureConn records writes; the tests never read from it.
type captureConn struct {
	local netip.AddrPort
	mu    *sync.Mutex
	out   *[]captured
	fail  bool
}

func (c *captureConn) ReadFromUDPAddrPort([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, net.ErrClosed
}

func (c *captureConn) WriteToUDPAddrPort(b []byte, to netip.AddrPort) (int, error) {
	if c.fail {
		return 0, errors.New("write failed")
	}
	c.mu.Lock()
	*c.out = append(*c.out, captured{b: append([]byte(nil), b...), from: c.local, to: to})
	c.mu.Unlock()
	return len(b), nil
}

// rig is the server's packet path without sockets: a Server whose listeners
// write into a shared capture list; process is called directly.
type rig struct {
	t     *testing.T
	s     *Server
	reg   *Registry
	clk   *testkit.StepClock // a step back tests a server clock set back
	ls    []*listener
	rds   []*reader
	out   []captured
	outMu sync.Mutex
	stats readerStats
}

type rigOpts struct {
	reg     RegistryConfig
	noExtra bool
	alt     bool
	srcRate Rate
}

func newRig(t *testing.T, o rigOpts) *rig {
	t.Helper()
	r := &rig{t: t, clk: testkit.NewStepClock(t, time.Time{})}
	o.reg.Clock = r.clk
	r.reg = NewRegistry(o.reg)
	if o.srcRate == (Rate{}) {
		o.srcRate = Rate{PerSec: -1}
	}
	r.s = &Server{cfg: ServerConfig{Registry: r.reg, NoExtraReply: o.noExtra}, reg: r.reg, src: newSourceLimiter(o.srcRate, 4096)}
	mk := func(a string) *captureConn {
		return &captureConn{local: netip.MustParseAddrPort(a), mu: &r.outMu, out: &r.out}
	}
	p := &pool{conns: []packetConn{mk("198.51.100.1:40999")}, ports: []uint16{40999}}
	for i := range 3 {
		a := netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), uint16(3478+i))
		r.ls = append(r.ls, &listener{id: uint8(i), pi: uint8(i), slots: 1, fam: protocol.FamilyUDP4, port: a.Port(), advs: []netip.Addr{a.Addr()}, conn: mk(a.String()), pool: p})
	}
	if o.alt {
		ap := &pool{conns: []packetConn{mk("198.51.100.2:41999")}, ports: []uint16{41999}}
		r.s.altPools[0] = ap
		r.ls = append(r.ls, &listener{id: 8, og: 1, slots: 1, group: 1, fam: protocol.FamilyUDP4, alt: true, flags: slotAlt,
			port: 3478, advs: []netip.Addr{netip.MustParseAddr("198.51.100.2")}, conn: mk("198.51.100.2:3478"), pool: ap})
	}
	for _, l := range r.ls {
		r.rds = append(r.rds, newReader(r.s, l, &r.stats))
	}
	return r
}

// deliver runs one datagram through listener i and returns the replies.
func (r *rig) deliver(i int, pkt []byte, src netip.AddrPort) []captured {
	r.outMu.Lock()
	r.out = r.out[:0]
	r.outMu.Unlock()
	r.rds[i].process(pkt, src, netip.Addr{})
	r.outMu.Lock()
	defer r.outMu.Unlock()
	return append([]captured(nil), r.out...)
}

// client is a session client: its codec and its window over server replies.
type client struct {
	t     *testing.T
	codec *udpwire.Codec
	win   udpwire.SeqWindow
}

func newClient(t *testing.T, token protocol.Token, route protocol.RouteID, role udpwire.Role) *client {
	t.Helper()
	c, err := udpwire.NewCodec(token, route, role, udpwire.PadPolicy{Min: 64, Max: 128}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &client{t: t, codec: c}
}

func (c *client) probe(o probetest.Probe) []byte {
	c.t.Helper()
	pkt, err := probetest.Seal(c.codec, o)
	if err != nil {
		c.t.Fatal(err)
	}
	return pkt
}

// open decodes a server reply as the client's read pump would.
func (c *client) open(b []byte) (udpwire.Header, udpwire.TLVs, bool) {
	return probetest.Open(c.codec, b, make([]byte, len(b)))
}

func register(t *testing.T, reg *Registry, id string, token protocol.Token, route protocol.RouteID) *handle {
	t.Helper()
	h, err := reg.register(nat.Registration{SessionID: id, Route: route, Token: token, TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

var srcA = netip.MustParseAddrPort("203.0.113.5:40000")
