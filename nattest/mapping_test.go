package nattest

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"
)

// threeObservers returns o1 and o2 on one IP (different ports) and o3 on
// another IP.
func threeObservers(t *testing.T, n *Network) (o1, o2, o3 Conn) {
	t.Helper()
	h1, o1 := observer(t, n, 3478)
	o2 = listenOn(t, h1, "udp4", netip.AddrPortFrom(h1.Addrs()[0], 3479))
	_, o3 = observer(t, n, 3478)
	return o1, o2, o3
}

func TestMappingBehaviour(t *testing.T) {
	cases := []struct {
		m                  Mapping
		sameIP, otherIP    bool // o1 vs o2 (same IP), o1 vs o3 (other IP)
		mappingsPerSockets int
	}{
		{EIM, true, true, 1},
		{ADM, true, false, 2},
		{APDM, false, false, 3},
	}
	for _, tc := range cases {
		t.Run(tc.m.String(), func(t *testing.T) {
			n := newNet(t)
			o1, o2, o3 := threeObservers(t, n)
			nat := n.NAT(NATConfig{Mapping: tc.m, PortAlloc: Sequential})
			c := listen(t, nat.Host(), 4000)
			m1, m2, m3 := srcAt(t, c, o1), srcAt(t, c, o2), srcAt(t, c, o3)
			if got := m1 == m2; got != tc.sameIP {
				t.Errorf("same-IP mappings equal = %v, want %v (%v %v)", got, tc.sameIP, m1, m2)
			}
			if got := m1 == m3; got != tc.otherIP {
				t.Errorf("cross-IP mappings equal = %v, want %v (%v %v)", got, tc.otherIP, m1, m3)
			}
			if again := srcAt(t, c, o1); again != m1 {
				t.Errorf("mapping not reused: %v then %v", m1, again)
			}
			st := nat.Stats()
			if st.MappingsCreated != uint64(tc.mappingsPerSockets) || st.MappingsActive != tc.mappingsPerSockets {
				t.Errorf("created %d active %d, want %d", st.MappingsCreated, st.MappingsActive, tc.mappingsPerSockets)
			}
		})
	}
}

// TestFilteringBehaviour checks which sources reach a mapping that has sent
// only to o1.
func TestFilteringBehaviour(t *testing.T) {
	cases := []struct {
		f              Filtering
		fromO2, fromO3 bool // same IP other port; other IP
	}{
		{EIF, true, true},
		{ADF, true, false},
		{APDF, false, false},
		{Open, true, true}, // as EIF on a translating NAT
	}
	for _, tc := range cases {
		t.Run(tc.f.String(), func(t *testing.T) {
			n := newNet(t)
			o1, o2, o3 := threeObservers(t, n)
			nat := n.NAT(NATConfig{Mapping: EIM, Filtering: tc.f})
			c := listen(t, nat.Host(), 4000)
			m := srcAt(t, c, o1)
			send(t, o1, m, "o1")
			send(t, o2, m, "o2")
			send(t, o3, m, "o3")
			got := map[string]bool{}
			for queued(c) > 0 {
				s, _ := recvNow(t, c)
				got[s] = true
			}
			if !got["o1"] || got["o2"] != tc.fromO2 || got["o3"] != tc.fromO3 {
				t.Fatalf("received %v", got)
			}
			wantFiltered := 0
			for _, reached := range []bool{tc.fromO2, tc.fromO3} {
				if !reached {
					wantFiltered++
				}
			}
			if st := nat.Stats(); st.FilteredInbound != uint64(wantFiltered) {
				t.Fatalf("FilteredInbound = %d, want %d", st.FilteredInbound, wantFiltered)
			}
		})
	}
}

// TestMappingFilteringMatrix sends unsolicited packets from o2 and o3 to the
// mapping created towards o1, for every Mapping x Filtering combination.
// Permissions belong to the mapping: under ADM and APDM the mapping towards
// o1 has sent nothing to o3.
func TestMappingFilteringMatrix(t *testing.T) {
	for _, m := range []Mapping{EIM, ADM, APDM} {
		for _, f := range []Filtering{EIF, ADF, APDF} {
			t.Run(fmt.Sprintf("%v-%v", m, f), func(t *testing.T) {
				n := newNet(t)
				o1, o2, o3 := threeObservers(t, n)
				nat := n.NAT(NATConfig{Mapping: m, Filtering: f, PortAlloc: Random})
				c := listen(t, nat.Host(), 4000)
				m1 := srcAt(t, c, o1)
				srcAt(t, c, o3) // the internal endpoint also talks to o3, through another mapping unless EIM
				send(t, o2, m1, "x")
				send(t, o3, m1, "y")
				want := 0
				if f == EIF || f == ADF {
					want++ // o2 shares o1's IP
				}
				if f == EIF || m == EIM {
					want++ // o3 is permitted on m1 only when m1 is the mapping that sent to it
				}
				if got := drain(c); got != want {
					t.Fatalf("%d unsolicited packets delivered, want %d", got, want)
				}
			})
		}
	}
}

func TestInboundWithoutMappingFiltered(t *testing.T) {
	n := newNet(t)
	_, o := observer(t, n, 1000)
	nat := n.NAT(FullCone())
	c := listen(t, nat.Host(), 4000)
	send(t, o, netip.AddrPortFrom(ext(t, nat), 4000), "unsolicited")
	expectNone(t, c)
	if st := nat.Stats(); st.FilteredInbound != 1 || st.MappingsCreated != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestPortPreserve(t *testing.T) {
	n := newNet(t)
	_, o := observer(t, n, 1000)
	nat := n.NAT(NATConfig{PortAlloc: Preserve})
	ca := listen(t, nat.Host(), 40000)
	cb := listen(t, nat.Host(), 40000) // the same internal port on another host
	ma, mb := srcAt(t, ca, o), srcAt(t, cb, o)
	if ma.Port() != 40000 {
		t.Fatalf("port not preserved: %v", ma)
	}
	if mb.Port() == 40000 || mb.Addr() != ma.Addr() {
		t.Fatalf("conflict not resolved: %v", mb)
	}
	// The fallback is the NAT-wide sequential cursor.
	cc := listen(t, nat.Host(), 40000)
	if mc := srcAt(t, cc, o); int(mc.Port()) != int(mb.Port())+1 {
		t.Fatalf("fallback not sequential: %v after %v", mc, mb)
	}
}

func TestPortPreserveOutsideRange(t *testing.T) {
	n := newNet(t)
	_, o := observer(t, n, 1000)
	cfg := NATConfig{PortRange: [2]uint16{20000, 20099}}
	nat := n.NAT(cfg)
	m := srcAt(t, listen(t, nat.Host(), 5000), o)
	if m.Port() < 20000 || m.Port() > 20099 {
		t.Fatalf("port %d outside the range", m.Port())
	}
}

func TestPortSequentialStep(t *testing.T) {
	for _, step := range []int{1, 2, -1, -2, 7} {
		t.Run(fmt.Sprint(step), func(t *testing.T) {
			n := newNet(t)
			nat := n.NAT(SymmetricSeq(step))
			c := listen(t, nat.Host(), 5555)
			prev := -1
			for i := range 6 {
				_, o := observer(t, n, uint16(2000+i))
				p := int(srcAt(t, c, o).Port())
				if prev >= 0 && p-prev != step {
					t.Fatalf("delta %d, want %d", p-prev, step)
				}
				prev = p
			}
		})
	}
}

func TestPortSequentialWrapsAndSkipsBusy(t *testing.T) {
	n := newNet(t)
	cfg := SymmetricSeq(1)
	cfg.PortRange = [2]uint16{2003, 2000} // reversed bounds are accepted
	nat := n.NAT(cfg)
	c := listen(t, nat.Host(), 5555)
	seen := map[uint16]bool{}
	for i := range 4 {
		_, o := observer(t, n, uint16(3000+i))
		p := srcAt(t, c, o).Port()
		if p < 2000 || p > 2003 || seen[p] {
			t.Fatalf("port %d out of range or reused (%v)", p, seen)
		}
		seen[p] = true
	}
	// The range is exhausted: a fifth mapping cannot be created.
	_, o := observer(t, n, 3999)
	send(t, c, addrOf(o), "x")
	expectNone(t, o)
	if st := nat.Stats(); st.Dropped.PortExhausted != 1 {
		t.Fatalf("PortExhausted = %d", st.Dropped.PortExhausted)
	}
}

// TestPortPreserveThenRandom: under APDM a fresh socket's first mapping
// keeps its port (PRESRND); its later ones, whose port is taken by
// the first, are random; another socket keeps its own port in turn.
func TestPortPreserveThenRandom(t *testing.T) {
	n := newNet(t)
	nat := n.NAT(SymmetricPreserveRandom())
	for _, local := range []uint16{40000, 40001} {
		c := listen(t, nat.Host(), local)
		var got []uint16
		for i := range 3 {
			_, o := observer(t, n, uint16(6000+int(local)%2*10+i))
			got = append(got, srcAt(t, c, o).Port())
		}
		if got[0] != local || got[1] == local || got[2] == local || got[1] == got[2] {
			t.Fatalf("socket %d: ports %v, want %d first and then others", local, got, local)
		}
	}
	if PreserveThenRandom.String() != "PreserveThenRandom" {
		t.Fatal("name")
	}
}

// TestPortSequentialDownWraps: a downward allocator (SYMSEQ-1) goes
// from the low end of its range to the high end, one step.
func TestPortSequentialDownWraps(t *testing.T) {
	n := newNet(t)
	cfg := SymmetricSeq(-1)
	cfg.PortRange = [2]uint16{2000, 2003}
	nat := n.NAT(cfg)
	c := listen(t, nat.Host(), 5555)
	var got []int
	for i := range 4 {
		_, o := observer(t, n, uint16(3000+i))
		got = append(got, int(srcAt(t, c, o).Port()))
	}
	for i := 1; i < len(got); i++ {
		if d := got[i] - got[i-1]; d != -1 && d != 3 {
			t.Fatalf("ports %v: step %d, want -1 or the wrap +3", got, d)
		}
	}
}

// TestPortSequentialEvenStepOrbit: a step that shares a factor with the
// range size visits only part of it; allocation falls back to single steps
// instead of failing.
func TestPortSequentialEvenStepOrbit(t *testing.T) {
	n := newNet(t)
	cfg := SymmetricSeq(2)
	cfg.PortRange = [2]uint16{3000, 3003}
	nat := n.NAT(cfg)
	c := listen(t, nat.Host(), 5555)
	seen := map[uint16]bool{}
	for i := range 4 {
		_, o := observer(t, n, uint16(100+i))
		seen[srcAt(t, c, o).Port()] = true
	}
	if len(seen) != 4 {
		t.Fatalf("ports %v, want all four", seen)
	}
}

func TestPortRandomSeeded(t *testing.T) {
	ports := func(seed int64) []uint16 {
		n := newNet(t, WithSeed(seed))
		cfg := SymmetricRandom()
		cfg.PortRange = [2]uint16{10000, 10999}
		nat := n.NAT(cfg)
		c := listen(t, nat.Host(), 5555)
		var out []uint16
		for i := range 20 {
			_, o := observer(t, n, uint16(3000+i))
			p := srcAt(t, c, o).Port()
			if p < 10000 || p > 10999 {
				t.Fatalf("port %d out of range", p)
			}
			out = append(out, p)
		}
		return out
	}
	a, b, c := ports(7), ports(7), ports(8)
	if !slices.Equal(a, b) {
		t.Fatalf("the same seed differs:\n%v\n%v", a, b)
	}
	if slices.Equal(a, c) {
		t.Fatalf("different seeds gave the same ports %v", a)
	}
	seq := 0
	for i := 1; i < len(a); i++ {
		if a[i] == a[i-1]+1 {
			seq++
		}
	}
	if seq > 3 {
		t.Fatalf("random allocation looks sequential: %v", a)
	}
}

// TestPortRandomNearlyFull: when almost every port is taken, allocation
// still finds the last free one.
func TestPortRandomNearlyFull(t *testing.T) {
	n := newNet(t)
	cfg := SymmetricRandom()
	cfg.PortRange = [2]uint16{4000, 4199}
	nat := n.NAT(cfg)
	c := listen(t, nat.Host(), 5555)
	h, o := observer(t, n, 1)
	for i := range 200 {
		send(t, c, netip.AddrPortFrom(h.Addrs()[0], uint16(1000+i)), "x")
	}
	send(t, c, addrOf(o), "last")
	if st := nat.Stats(); st.MappingsActive != 200 || st.Dropped.PortExhausted != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func TestPortPreserveThenSequential(t *testing.T) {
	n := newNet(t)
	_, o := observer(t, n, 1000)
	nat := n.NAT(NATConfig{PortAlloc: PreserveThenSequential, PortStep: 2})
	m1 := srcAt(t, listen(t, nat.Host(), 30000), o)
	m2 := srcAt(t, listen(t, nat.Host(), 30000), o)
	m3 := srcAt(t, listen(t, nat.Host(), 30000), o)
	if m1.Port() != 30000 || m2.Port() != 30002 || m3.Port() != 30004 {
		t.Fatalf("got %v %v %v", m1, m2, m3)
	}
}

func TestPortPool(t *testing.T) {
	n := newNet(t)
	cfg := SymmetricRandom()
	cfg.PortAlloc = Pool(32767, 31744)
	nat := n.NAT(cfg)
	c := listen(t, nat.Host(), 5555)
	lo, hi := uint16(65535), uint16(0)
	for i := range 30 {
		_, o := observer(t, n, uint16(3000+i))
		p := srcAt(t, c, o).Port()
		if p < 31744 || p > 32767 {
			t.Fatalf("port %d outside the pool", p)
		}
		lo, hi = min(lo, p), max(hi, p)
	}
	if hi-lo < 200 {
		t.Fatalf("pool allocation not spread: [%d, %d]", lo, hi)
	}
	if s := cfg.PortAlloc.String(); s != "Pool(31744,32767)" {
		t.Fatalf("String = %q", s)
	}
}

func TestMappingTimeoutAndOutboundRefresh(t *testing.T) {
	n, clk := fakeNet(t)
	_, o := observer(t, n, 1000)
	nat := n.NAT(NATConfig{Mapping: EIM, Filtering: APDF, PortAlloc: Random, MappingTimeout: 30 * time.Second})
	c := listen(t, nat.Host(), 4000)
	m := srcAt(t, c, o)
	for range 3 { // an outbound keepalive every 20 s keeps the mapping
		clk.Advance(20 * time.Second)
		if got := srcAt(t, c, o); got != m {
			t.Fatalf("mapping changed despite refresh: %v -> %v", m, got)
		}
	}
	// Inbound traffic does not refresh (RFC 4787 REQ-6 default).
	clk.Advance(20 * time.Second)
	send(t, o, m, "in")
	recvNow(t, c)
	clk.Advance(10 * time.Second) // 30 s since the last outbound packet
	send(t, o, m, "late")
	expectNone(t, c)
	st := nat.Stats()
	if st.MappingsExpired != 1 || st.MappingsActive != 0 || st.FilteredInbound != 1 {
		t.Fatalf("stats after expiry %+v", st)
	}
	if again := srcAt(t, c, o); again == m {
		t.Fatalf("expired mapping reused %v under random allocation", again)
	}
}

func TestExpiredMappingReallocatedOnOutbound(t *testing.T) {
	n, clk := fakeNet(t)
	_, o := observer(t, n, 1000)
	nat := n.NAT(NATConfig{Mapping: EIM, PortAlloc: Sequential, MappingTimeout: 5 * time.Second})
	c := listen(t, nat.Host(), 4000)
	m := srcAt(t, c, o)
	clk.Advance(6 * time.Second)
	if again := srcAt(t, c, o); again.Port() != m.Port()+1 {
		t.Fatalf("after expiry got %v, want the next sequential port after %v", again, m)
	}
	if st := nat.Stats(); st.MappingsExpired != 1 || st.MappingsCreated != 2 {
		t.Fatalf("stats %+v", st)
	}
}

func TestRefreshOnInbound(t *testing.T) {
	n, clk := fakeNet(t)
	_, o := observer(t, n, 1000)
	nat := n.NAT(NATConfig{Mapping: EIM, Filtering: APDF, MappingTimeout: 10 * time.Second, RefreshOnInbound: true})
	c := listen(t, nat.Host(), 4000)
	m := srcAt(t, c, o)
	for range 5 {
		clk.Advance(8 * time.Second)
		send(t, o, m, "keep")
		recvNow(t, c)
	}
	if st := nat.Stats(); st.MappingsExpired != 0 || st.MappingsActive != 1 {
		t.Fatalf("inbound refresh did not keep the mapping: %+v", st)
	}
}

func TestPermissionExpiresIndependently(t *testing.T) {
	n, clk := fakeNet(t)
	_, o1 := observer(t, n, 1000)
	_, peer := observer(t, n, 2000)
	nat := n.NAT(NATConfig{Mapping: EIM, Filtering: APDF, MappingTimeout: 30 * time.Second})
	c := listen(t, nat.Host(), 4000)
	m := srcAt(t, c, peer) // opens peer
	for range 4 {
		clk.Advance(10 * time.Second)
		srcAt(t, c, o1) // keeps the mapping alive, not the permission of peer
	}
	send(t, peer, m, "x")
	expectNone(t, c)
	if mi := nat.Mappings(); len(mi) != 1 || len(mi[0].Permits) != 1 || mi[0].Permits[0] != addrOf(o1) {
		t.Fatalf("mappings %+v", mi)
	}
}

// TestPermissionSweep: a mapping that sprays many destinations forgets the
// stale permissions instead of keeping them for ever.
func TestPermissionSweep(t *testing.T) {
	n, clk := fakeNet(t)
	h, _ := observer(t, n, 1)
	nat := n.NAT(NATConfig{Filtering: APDF, MappingTimeout: 5 * time.Second})
	c := listen(t, nat.Host(), 4000)
	for i := range 100 {
		send(t, c, netip.AddrPortFrom(h.Addrs()[0], uint16(10000+i)), "old")
	}
	clk.Advance(4 * time.Second)
	send(t, c, netip.AddrPortFrom(h.Addrs()[0], 10000), "keepalive")
	clk.Advance(2 * time.Second) // 99 permissions are stale now
	for i := range 40 {
		send(t, c, netip.AddrPortFrom(h.Addrs()[0], uint16(30000+i)), "new")
	}
	front := nat.lru.Front()
	if front == nil {
		t.Fatal("no mapping")
	}
	if m := front.Value.(*mapEntry); len(m.perm) > 64 {
		t.Fatalf("%d permissions kept, stale ones not swept", len(m.perm))
	}
	if got := len(nat.Mappings()[0].Permits); got != 41 {
		t.Fatalf("%d live permits, want 41", got)
	}
}

func TestNoTimeout(t *testing.T) {
	n, clk := fakeNet(t)
	_, o := observer(t, n, 1000)
	nat := n.NAT(NATConfig{MappingTimeout: NoTimeout})
	c := listen(t, nat.Host(), 4000)
	m := srcAt(t, c, o)
	clk.Advance(24 * time.Hour)
	send(t, o, m, "x")
	recvNow(t, c)
	if mi := nat.Mappings(); len(mi) != 1 || !mi[0].Expires.IsZero() {
		t.Fatalf("mappings %+v", mi)
	}
}

func TestMaxMappingsLRUEviction(t *testing.T) {
	n := newNet(t)
	nat := n.NAT(NATConfig{Mapping: APDM, Filtering: APDF, PortAlloc: Sequential, MaxMappings: 3})
	c := listen(t, nat.Host(), 4000)
	var obs []Conn
	var maps []netip.AddrPort
	for i := range 3 {
		_, o := observer(t, n, uint16(1000+i))
		obs = append(obs, o)
		maps = append(maps, srcAt(t, c, o))
	}
	srcAt(t, c, obs[0]) // obs[0] becomes most recently used; obs[1] is the LRU
	_, o4 := observer(t, n, 1004)
	srcAt(t, c, o4)
	if st := nat.Stats(); st.MappingsActive != 3 || st.MappingsEvicted != 1 {
		t.Fatalf("stats %+v", st)
	}
	send(t, obs[1], maps[1], "evicted")
	expectNone(t, c)
	send(t, obs[0], maps[0], "kept")
	recvNow(t, c)
}

func TestMappingsSnapshot(t *testing.T) {
	n, clk := fakeNet(t)
	_, o := observer(t, n, 1000)
	nat := n.NAT(SymmetricSeq(1))
	h := nat.Host()
	c := listen(t, h, 4000)
	m := srcAt(t, c, o)
	clk.Advance(time.Second)
	send(t, o, m, "in")
	mi := nat.Mappings()
	if len(mi) != 1 {
		t.Fatalf("%d mappings", len(mi))
	}
	got := mi[0]
	if got.Internal != netip.AddrPortFrom(h.Addrs()[0], 4000) || got.External != m || got.Remote != addrOf(o) || got.Out != 1 || got.In != 1 {
		t.Fatalf("mapping %+v", got)
	}
	if want := got.LastOut.Add(30 * time.Second); !got.Expires.Equal(want) {
		t.Fatalf("expires %v, want %v", got.Expires, want)
	}
	if got.LastIn.Sub(got.LastOut) != time.Second {
		t.Fatalf("lastIn %v lastOut %v", got.LastIn, got.LastOut)
	}
}

func TestNATConfigDefaults(t *testing.T) {
	c := NATConfig{PortRange: [2]uint16{0, 100}, PortAlloc: PortAlloc(77), MappingTimeout: -5, ScanDefense: &ScanDefense{MaxConsecutiveRun: -1}}.normalized()
	if c.PortStep != 1 || c.PortRange != [2]uint16{1, 100} || c.PortAlloc != Preserve || c.MappingTimeout != NoTimeout || c.MaxMappings != defaultMaxMappings {
		t.Fatalf("normalized %+v", c)
	}
	sd := *c.ScanDefense
	if sd.DistinctDstPorts != 300 || sd.MaxConsecutiveRun != 0 || sd.UnsolicitedInbound != 500 || sd.Window != 10*time.Second || sd.BanFor != time.Minute {
		t.Fatalf("scan defense %+v", sd)
	}
	z := NATConfig{}.normalized()
	if z.PortRange != [2]uint16{1024, 65535} || z.MappingTimeout != 30*time.Second {
		t.Fatalf("zero config %+v", z)
	}
	if p := (NATConfig{PortAlloc: Pool(0, 0)}).normalized().PortAlloc; p != Pool(1, 1) {
		t.Fatalf("Pool(0,0) normalized to %v", p)
	}
	for _, s := range []fmt.Stringer{EIM, ADM, APDM, Identity, Mapping(9),
		EIF, ADF, APDF, Open, Filtering(9),
		Preserve, Sequential, Random, PreserveThenSequential, PortAlloc(77),
		SingleExit, PerSourcePort, PerDestIP, RoundRobin, ExitPolicy(9),
		NoNAT, NPTv6, NAT66, IPv6Mode(9)} {
		if s.String() == "" {
			t.Fatalf("empty String for %#v", s)
		}
	}
}

// An inbound packet that an endpoint-dependent mapping's filter
// admits — ADF from another port of a contacted IP, EIF from anyone — opens
// a flow as conntrack does: the reply leaves through the mapping that
// admitted the packet, so its sender sees the address it sent to, instead
// of a new mapping its own filter would refuse. Under APDF nothing new is
// admitted; once the mapping expires, so do its flows.
func TestRepliesFollowAdmittingMapping(t *testing.T) {
	cases := []struct {
		m       Mapping
		f       Filtering
		fromO2  bool // o2: same IP as o1, another port
		fromO3  bool // o3: another IP
		mapping int  // mappings the internal host ends with
	}{
		{APDM, ADF, true, false, 1},
		{APDM, EIF, true, true, 1},
		{ADM, EIF, true, true, 1},
		{APDM, APDF, false, false, 1},
	}
	for _, tc := range cases {
		t.Run(tc.m.String()+"/"+tc.f.String(), func(t *testing.T) {
			n, clk := fakeNet(t)
			o1, o2, o3 := threeObservers(t, n)
			nat := n.NAT(NATConfig{Mapping: tc.m, Filtering: tc.f, PortAlloc: Sequential, MappingTimeout: 30 * time.Second})
			c := listen(t, nat.Host(), 4000)
			m := srcAtAfter(t, clk, c, o1)
			for _, o := range []struct {
				obs  Conn
				in   bool
				name string
			}{{o2, tc.fromO2, "o2"}, {o3, tc.fromO3, "o3"}} {
				send(t, o.obs, m, "in")
				clk.Advance(time.Second)
				if got := queued(c) > 0; got != o.in {
					t.Fatalf("%s admitted = %v, want %v", o.name, got, o.in)
				}
				if !o.in {
					continue
				}
				_, from := recvNow(t, c)
				send(t, c, from, "reply")
				clk.Advance(time.Second)
				if _, src := recvNow(t, o.obs); src != m {
					t.Fatalf("reply to %s left from %v, not the admitting mapping %v", o.name, src, m)
				}
			}
			if st := nat.Stats(); st.MappingsActive != tc.mapping {
				t.Fatalf("%d mappings, want %d", st.MappingsActive, tc.mapping)
			}
			if !tc.fromO2 {
				return
			}
			// Expired with its mapping, the flow is gone: a reply to o2 now
			// takes a fresh mapping.
			clk.Advance(time.Minute)
			if src := srcAtAfter(t, clk, c, o2); src == m {
				t.Fatalf("a reply after expiry reused %v", m)
			}
		})
	}
}

// TestRepliesFollowAdmittingMappingAtScale: the flows that admitted inbound
// packets open are bounded by MaxMappings, not by a small fixed number: a
// mapping that admits a hundred peers answers each through itself.
func TestRepliesFollowAdmittingMappingAtScale(t *testing.T) {
	n := newNet(t)
	nat := n.NAT(NATConfig{Mapping: APDM, Filtering: EIF, PortAlloc: Sequential})
	c := listen(t, nat.Host(), 4000)
	_, o := observer(t, n, 1)
	m := srcAt(t, c, o)
	for i := range 100 {
		_, peer := observer(t, n, uint16(2+i))
		send(t, peer, m, "in")
		_, from := recvNow(t, c)
		send(t, c, from, "reply")
		if _, src := recvNow(t, peer); src != m {
			t.Fatalf("reply to peer %d left from %v, not the admitting mapping %v", i, src, m)
		}
	}
	if st := nat.Stats(); st.MappingsActive != 1 {
		t.Fatalf("%d mappings, want 1", st.MappingsActive)
	}
}
