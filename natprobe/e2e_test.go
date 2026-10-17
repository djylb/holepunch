package natprobe_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/internal/probe"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/protocol"
)

// pumpSock is a client socket; the test plays the runtime: the socket's only
// reader (the read pump) decodes datagrams and hands probe-class packets to
// the prober, which only writes.
type pumpSock struct {
	id   uint8
	conn *net.UDPConn
}

func (s *pumpSock) ID() uint8             { return s.id }
func (s *pumpSock) Local() netip.AddrPort { return s.conn.LocalAddr().(*net.UDPAddr).AddrPort() }
func (s *pumpSock) WriteTo(b []byte, to netip.AddrPort) error {
	_, err := s.conn.WriteToUDPAddrPort(b, to)
	return err
}

type clientRT struct {
	codec *udpwire.Codec
	mu    sync.Mutex
	win   udpwire.SeqWindow // replies of the server role
	p     *probe.Prober
	wg    sync.WaitGroup
	socks []*pumpSock
}

func (c *clientRT) open(ip netip.Addr, id uint8) (*pumpSock, error) {
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, 0)))
	if err != nil {
		return nil, err
	}
	s := &pumpSock{id: id, conn: conn}
	c.socks = append(c.socks, s)
	c.wg.Go(func() { c.pump(s) })
	return s, nil
}

func (c *clientRT) pump(s *pumpSock) {
	buf := make([]byte, 2048)
	scratch := make([]byte, 2048)
	for {
		n, from, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		pkt := buf[:n]
		if probe.IsSTUN(pkt) {
			c.p.DeliverSTUN(s.id, from, pkt, time.Now())
			continue
		}
		var h udpwire.Header
		var tl udpwire.TLVs
		if c.codec.Open(pkt, scratch, &h, &tl) != udpwire.OK || c.codec.CheckRole(&h) != udpwire.OK {
			continue
		}
		if h.Role == udpwire.RoleServer {
			c.mu.Lock()
			fresh := c.win.Accept(h.Seq)
			c.mu.Unlock()
			if !fresh {
				continue
			}
		}
		c.p.Deliver(s.id, from, &h, &tl, time.Now())
	}
}

func (c *clientRT) close() {
	for _, s := range c.socks {
		_ = s.conn.Close()
	}
	c.wg.Wait()
}

// The full stack on loopback: natprobe.Server, internal/probe.Prober and
// Handle.Merge, for each family the host has.
func TestEndToEndLoopback(t *testing.T) {
	families := []struct {
		f  protocol.Family
		ip netip.Addr
	}{{protocol.FamilyUDP4, netip.MustParseAddr("127.0.0.1")}, {protocol.FamilyUDP6, netip.MustParseAddr("::1")}}
	for _, fam := range families {
		t.Run(string(fam.f), func(t *testing.T) {
			c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(fam.ip, 0)))
			if err != nil {
				t.Skip("no loopback for", fam.f)
			}
			_ = c.Close()
			runEndToEnd(t, fam.f, fam.ip)
		})
	}
}

func runEndToEnd(t *testing.T, f protocol.Family, ip netip.Addr) {
	reg := natprobe.NewRegistry(natprobe.RegistryConfig{})
	srv, err := natprobe.NewServer(natprobe.ServerConfig{Registry: reg, Groups: []natprobe.ObserverGroup{{Bind: ip}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := srv.Close(); err != nil {
			t.Error(err)
		}
	}()
	token, route := protocol.NewToken(), protocol.NewRouteID()
	h, err := nat.RegisterProbe(reg, nat.Registration{SessionID: "e2e-session", Route: route, Token: token, TTL: 25 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	codec, err := udpwire.NewCodec(token, route, udpwire.RoleResponder, udpwire.PadPolicy{Min: 64, Max: 160}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rt := &clientRT{codec: codec}
	defer rt.close()
	primary, err := rt.open(ip, nat.SocketID(f, nat.IndexPrimary))
	if err != nil {
		t.Fatal(err)
	}
	spec := probe.Spec{Codec: codec, Family: f, Timeout: 2 * time.Second, Probe: protocol.ProbeSpec{V: protocol.ProbeSpecVersion,
		Observers: srv.Observers(f), ExtraReply: true, SecondSocket: true}}
	rt.p = probe.New(spec, primary, nil, func() (probe.SocketHandle, error) {
		return rt.open(ip, nat.SocketID(f, nat.IndexSecond))
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res := rt.p.Run(ctx)
	tr := res.Traits
	if res.Failure != "" || tr.NoNAT != protocol.TriTrue || tr.Mapping != protocol.MapEIM || tr.MappingConf != protocol.ConfHigh ||
		tr.Filtering != protocol.FiltEIF || tr.Samples != 3 || tr.Observed != primary.Local() {
		t.Fatalf("result %+v", res)
	}
	if res.Sent.Primary != 3 || res.Sent.Second != 0 || res.Clock.RTTMs == 0 {
		t.Fatalf("sent %+v clock %+v", res.Sent, res.Clock)
	}
	// hairpin over loopback: our own packet comes back on the same socket
	if hp := rt.p.Hairpin(ctx); hp != protocol.TriTrue {
		t.Fatalf("hairpin %v", hp)
	}

	fr := res.Table.Snapshot()
	fr.Traits = res.Traits
	rep := protocol.ProbeReport{SessionID: "e2e-session", Role: protocol.RoleResponder, Control: protocol.DefaultControlSpec(),
		Families: []protocol.FamilyReport{fr}, Clock: res.Clock, Transport: protocol.Transport{Mode: "quic"}}
	if err := rep.Validate(); err != nil {
		t.Fatal(err)
	}
	mem := natprobe.NewTraitsMemory(natprobe.TraitsMemoryConfig{})
	view, diag, err := h.Merge(protocol.RoleResponder, rep, mem, "c", false)
	if err != nil {
		t.Fatal(err)
	}
	if diag != (nat.MergeDiag{}) || len(view.Families) != 1 {
		t.Fatalf("diag %+v view %+v", diag, view)
	}
	fv := view.Families[0]
	if fv.Traits.Provisional || fv.Traits.Mapping != protocol.MapEIM || fv.Traits.Filtering != protocol.FiltEIF || fv.Traits.Samples != 3 {
		t.Fatalf("server traits %+v", fv.Traits)
	}
	want := protocol.Endpoint{Addr: primary.Local(), Source: protocol.EndpointServer, Socket: primary.id, Verified: true}
	if len(fv.Endpoints) != 1 || fv.Endpoints[0] != want {
		t.Fatalf("endpoints %+v", fv.Endpoints)
	}
	if len(h.Observations(protocol.RoleResponder)) != 3 {
		t.Fatal("observations")
	}
	// The prober is done once one extra arrived; the server's reader may
	// still be writing the other two, so their counters settle a little later.
	st := srv.Stats()
	for deadline := time.Now().Add(2 * time.Second); st.Extras < 3 && time.Now().Before(deadline); st = srv.Stats() {
		time.Sleep(time.Millisecond)
	}
	if st.Acks != 3 || st.Extras != 3 || st.BytesOut > st.BytesIn || st.Panics != 0 || st.BadAuth != 0 {
		t.Fatalf("server stats %+v", st)
	}
}
