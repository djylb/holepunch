package holepunch

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/leak"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

// sameNATScript punches two hosts behind one hairpinning NAT on their LAN
// and public endpoints from the primary sockets (TestSameNATPair).
func sameNATScript(w *world) *pairScript {
	return &pairScript{w: w, timeouts: testTimeouts(), round: func(k int, r protocol.Role, views [2]protocol.PeerView) protocol.RoundPlan {
		p := directPlan(k, r, views)
		for _, e := range views[1-roleIndex(r)].Families[0].Endpoints {
			if e.Source == protocol.EndpointLAN {
				p.Sides[0].Stages[0].Targets = append(p.Sides[0].Stages[0].Targets, e.Addr)
			}
		}
		return p
	}}
}

func sameNATHosts(w *world) [2]*nattest.Host {
	cfg := nattest.PortRestricted()
	cfg.Hairpin = true
	nat := w.n.NAT(cfg)
	return [2]*nattest.Host{nat.Host(), nat.Host()}
}

// wantMirrored checks that both sides hold the same paths, each seen from
// its own end, and reported them in punch_result and Diagnostics.
func wantMirrored(t *testing.T, pr *pairRun, n int) {
	t.Helper()
	var res [2]Result
	for i, r := range pr.res {
		res[i] = r.sess.Result()
		if len(res[i].ExtraPaths) != n-1 || len(r.sess.ExtraPacketConns()) != n-1 {
			t.Fatalf("client %d: %d extra paths %+v, want %d", i, len(res[i].ExtraPaths), res[i].ExtraPaths, n-1)
		}
		if got := pr.script.results[i]; got == nil || len(got.ExtraPaths) != n-1 {
			t.Fatalf("client %d punch_result %+v", i, got)
		}
		d := r.sess.Diagnostics()
		if len(d.ExtraPaths) != n-1 {
			t.Fatalf("client %d diagnostics extra paths %+v", i, d.ExtraPaths)
		}
		for _, p := range pr.script.results[i].ExtraPaths {
			if p.ConfirmedBy != d.Path.ConfirmedBy {
				t.Fatalf("client %d: extra path confirmed by %s, the primary by %s", i, p.ConfirmedBy, d.Path.ConfirmedBy)
			}
		}
		peers := []netip.AddrPort{res[i].Path.RemoteAddr}
		for _, p := range res[i].ExtraPaths {
			peers = append(peers, p.RemoteAddr)
		}
		if !slices.Equal(r.sess.ResidualFilter().Codec.Peers(), peers) {
			t.Fatalf("client %d: residual filter bound to %v, want %v", i, r.sess.ResidualFilter().Codec.Peers(), peers)
		}
	}
	all := func(r Result) []Path { return append([]Path{r.Path}, r.ExtraPaths...) }
	a, b := all(res[0]), all(res[1])
	for k := range a {
		if a[k].Family != b[k].Family || a[k].Kind != b[k].Kind {
			t.Fatalf("path %d: %s/%s and %s/%s", k, a[k].Family, a[k].Kind, b[k].Family, b[k].Kind)
		}
	}
	// No duplicates: paths differ in family, kind or a socket.
	for _, ps := range [][]Path{a, b} {
		for i := range ps {
			for j := range i {
				if ps[i].Family == ps[j].Family && ps[i].Kind == ps[j].Kind && ps[i].LocalAddr == ps[j].LocalAddr {
					t.Fatalf("duplicate paths %+v and %+v", ps[i], ps[j])
				}
			}
		}
	}
}

// echo sends a datagram over a handed-over path and wants it on the peer's
// socket of the same path.
func echo(t *testing.T, from, to net.PacketConn, dst netip.AddrPort) {
	t.Helper()
	got := make(chan error, 1)
	go func() {
		b := make([]byte, 1500)
		_ = to.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _, err := to.ReadFrom(b)
		_ = to.SetReadDeadline(time.Time{})
		got <- err
	}()
	if _, err := from.WriteTo([]byte("upper layer"), net.UDPAddrFromAddrPort(dst)); err != nil {
		t.Fatal(err)
	}
	if err := <-got; err != nil {
		t.Fatalf("no datagram over the path to %v: %v", dst, err)
	}
}

// Two hosts behind one hairpinning NAT, both allowed two paths: the LAN
// path and the public path through the NAT both carry the peer's packets,
// so the session hands over both — through the same primary sockets, told
// apart by their kind. Close closes every socket once.
func TestMultiPathLANAndPublic(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	var tracks [2]*leak.TrackingNetwork
	pr := runPairHosts(t, w, sameNATHosts(w), sameNATScript(w), func(i int, o *Options) {
		o.MaxPaths = 2
		tracks[i] = leak.NewTrackingNetwork(o.Network)
		o.Network = tracks[i]
	})
	defer pr.closeAll()
	wantSuccess(t, pr)
	wantMirrored(t, pr, 2)
	for i, r := range pr.res {
		res := r.sess.Result()
		kinds := []protocol.PathKind{res.Path.Kind, res.ExtraPaths[0].Kind}
		if !slices.Contains(kinds, protocol.PathLAN) || !slices.Contains(kinds, protocol.PathPublic) {
			t.Fatalf("client %d: kinds %v, want lan and public", i, kinds)
		}
		if r.sess.ExtraPacketConns()[0] != r.sess.PacketConn() {
			t.Fatalf("client %d: the two paths of the primary socket are on different conns", i)
		}
		if err := tracks[i].CheckOpen(1); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 2 {
		echo(t, pr.res[i].sess.PacketConn(), pr.res[1-i].sess.PacketConn(), pr.res[i].sess.Result().Path.RemoteAddr)
		echo(t, pr.res[i].sess.ExtraPacketConns()[0], pr.res[1-i].sess.ExtraPacketConns()[0], pr.res[i].sess.Result().ExtraPaths[0].RemoteAddr)
	}
	pr.closeAll()
	for i := range 2 {
		if err := tracks[i].CheckClosed(); err != nil {
			t.Fatal(err)
		}
	}
}

// dualStackScript punches IPv6 (unverified, self-reported) and IPv4 from
// the primary sockets of two dual-stack public hosts (TestDualStackUnverifiedV6
// with both families sending).
func dualStackScript(t *testing.T, w *world) *pairScript {
	ps := &pairScript{w: w, timeouts: testTimeouts()}
	ps.pair = func(p *protocol.PairFacts, views *[2]protocol.PeerView, reports [2]protocol.ProbeReport) {
		p.SharedFamilies = []protocol.Family{protocol.FamilyUDP6, protocol.FamilyUDP4}
		p.Unverified = map[protocol.Family]bool{protocol.FamilyUDP6: true}
		for i := range 2 {
			v6, ok := selfReported(reports[i], protocol.FamilyUDP6)
			if !ok {
				t.Errorf("client %d did not report its IPv6 family", i)
				continue
			}
			var rest []protocol.FamilyView
			for _, fv := range views[i].Families {
				if fv.Family != protocol.FamilyUDP6 {
					rest = append(rest, fv)
				}
			}
			views[i].Families = append([]protocol.FamilyView{v6}, rest...)
		}
	}
	ps.round = func(k int, r protocol.Role, views [2]protocol.PeerView) protocol.RoundPlan {
		peer := views[1-roleIndex(r)]
		side := func(f protocol.Family, to netip.AddrPort) protocol.FamilySide {
			return protocol.FamilySide{Family: f, Role: protocol.SideBoth, Sockets: 1, MaxPackets: 40, MaxPPS: 80, MaxNewPerSec: 100,
				MaxDistinctPorts: 16, Stages: []protocol.Stage{{Kind: protocol.StageDirect, Targets: []netip.AddrPort{to}, Repeats: 8}}}
		}
		return protocol.RoundPlan{Round: uint8(k), Variant: "dual_direct_r1", Budget: protocol.BudgetLight, WindowMs: 1200, Seed: 9,
			Sides: []protocol.FamilySide{
				side(protocol.FamilyUDP6, peer.Families[0].Endpoints[0].Addr),
				side(protocol.FamilyUDP4, peer.Families[1].Endpoints[0].Addr),
			}}
	}
	return ps
}

// Two dual-stack hosts allowed three paths: one path per family, on their
// own sockets — the Direct packets of the family heard second still go out
// after the first contact (keepAfterContact) — and no third, which would be
// a duplicate.
func TestMultiPathDualStack(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	hosts := [2]*nattest.Host{w.n.PublicHost(), w.n.PublicHost()}
	pr := runPairHosts(t, w, hosts, dualStackScript(t, w), func(_ int, o *Options) { o.MaxPaths = 3 })
	defer pr.closeAll()
	wantSuccess(t, pr)
	wantMirrored(t, pr, 2)
	for i, r := range pr.res {
		res := r.sess.Result()
		if res.Path.Family == res.ExtraPaths[0].Family || r.sess.ExtraPacketConns()[0] == r.sess.PacketConn() {
			t.Fatalf("client %d: paths %+v %+v", i, res.Path, res.ExtraPaths[0])
		}
	}
	for i := range 2 {
		echo(t, pr.res[i].sess.ExtraPacketConns()[0], pr.res[1-i].sess.ExtraPacketConns()[0], pr.res[i].sess.Result().ExtraPaths[0].RemoteAddr)
	}
}

// One path is today's behaviour: with MaxPaths 1 on either side the pair of
// TestMultiPathLANAndPublic hands over one path, and a side allowed more
// facing a side of one path neither commits an extra one nor waits for it.
func TestMaxPathsOne(t *testing.T) {
	t.Parallel()
	for _, mp := range [][2]int{{0, 0}, {2, 1}, {1, 2}} {
		w := newWorld(t)
		ps := sameNATScript(w)
		pr := runPairHosts(t, w, sameNATHosts(w), ps, func(i int, o *Options) { o.MaxPaths = mp[i] })
		wantSuccess(t, pr)
		wantMirrored(t, pr, 1)
		for i, r := range pr.res {
			if len(r.sess.ExtraPacketConns()) != 0 || len(ps.results[i].ExtraPaths) != 0 {
				t.Fatalf("MaxPaths %v, client %d: extra conns %v", mp, i, r.sess.ExtraPacketConns())
			}
		}
		if h := pr.res[0].sess.Diagnostics().Timing.Handover; h > 500*time.Millisecond {
			t.Fatalf("MaxPaths %v: handover took %v", mp, h)
		}
		pr.closeAll()
	}
}

// Close releases every port mapping before it closes any socket, closes a
// socket shared by two paths once, and reports the first error.
func TestSessionCloseAllPaths(t *testing.T) {
	_, h := simHost(t)
	var conns []net.PacketConn
	for range 2 {
		c, err := h.ListenPacket(context.Background(), "udp4", netip.AddrPort{}, "test")
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	var mu sync.Mutex
	var order []string
	rec := func(s string) {
		mu.Lock()
		order = append(order, s)
		mu.Unlock()
	}
	cc := []net.PacketConn{&closeSpy{PacketConn: conns[0], rec: rec, name: "a"}, &closeSpy{PacketConn: conns[1], rec: rec, name: "b"}}
	relErr := errors.New("release")
	s := &Session{conn: cc[0], extra: []net.PacketConn{cc[0], cc[1]}, releases: []func() error{
		func() error { rec("release-a"); return relErr },
		func() error { rec("release-b"); return nil },
	}}
	if err := s.Close(); !errors.Is(err, relErr) {
		t.Fatalf("Close = %v", err)
	}
	if want := []string{"release-a", "release-b", "close-a", "close-b"}; !slices.Equal(order, want) {
		t.Fatalf("order %v, want %v", order, want)
	}
	if err := s.Close(); !errors.Is(err, relErr) || len(order) != 4 {
		t.Fatalf("second Close = %v, order %v", err, order)
	}
}

type closeSpy struct {
	net.PacketConn
	rec  func(string)
	name string
}

func (c *closeSpy) Close() error {
	c.rec("close-" + c.name)
	return c.PacketConn.Close()
}

// Options.MaxPaths outside [0, protocol.MaxPaths] is an argument error.
func TestMaxPathsOption(t *testing.T) {
	for _, n := range []int{-1, protocol.MaxPaths + 1} {
		o := Options{ControlSecurity: protocol.ControlSecurityInsecureForTesting, MaxPaths: n}
		if e := validateOptions(nil, &o); e == nil || e.Detail != "max_paths" {
			t.Fatalf("MaxPaths %d: %v", n, e)
		}
	}
	o := Options{ControlSecurity: protocol.ControlSecurityInsecureForTesting, MaxPaths: protocol.MaxPaths}
	if e := validateOptions(nil, &o); e != nil {
		t.Fatal(e)
	}
}
