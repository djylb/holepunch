package nattest

import (
	"net"
	"net/netip"
	"testing"
)

func TestHairpin(t *testing.T) {
	for _, on := range []bool{false, true} {
		t.Run(map[bool]string{false: "off", true: "on"}[on], func(t *testing.T) {
			n := newNet(t)
			_, o := observer(t, n, 3478)
			cfg := PortRestricted()
			cfg.Hairpin = on
			nat := n.NAT(cfg)
			a := listen(t, nat.Host(), 4000)
			b := listen(t, nat.Host(), 5000)
			ma, mb := srcAt(t, a, o), srcAt(t, b, o)
			send(t, b, ma, "open") // opens b's filter towards ma; filtered at a, which never sent to mb
			send(t, a, mb, "hairpin")
			if !on {
				expectNone(t, b)
				expectNone(t, a)
				if st := nat.Stats(); st.Dropped.NoHairpin != 2 || st.HairpinDelivered != 0 || st.MappingsActive != 2 {
					t.Fatalf("stats %+v", st)
				}
				return
			}
			if s, src := recvNow(t, b); s != "hairpin" || src != ma {
				t.Fatalf("got %q from %v, want the source rewritten to %v", s, src, ma)
			}
			send(t, b, ma, "reply")
			if s, src := recvNow(t, a); s != "reply" || src != mb {
				t.Fatalf("got %q from %v", s, src)
			}
			if st := nat.Stats(); st.HairpinDelivered != 2 || st.FilteredInbound != 1 {
				t.Fatalf("stats %+v", st)
			}
		})
	}
}

func TestHairpinRespectsFiltering(t *testing.T) {
	n := newNet(t)
	_, o := observer(t, n, 3478)
	cfg := PortRestricted()
	cfg.Hairpin = true
	nat := n.NAT(cfg)
	a := listen(t, nat.Host(), 4000)
	b := listen(t, nat.Host(), 5000)
	srcAt(t, a, o)
	mb := srcAt(t, b, o)
	send(t, a, mb, "unsolicited")
	expectNone(t, b)
	if st := nat.Stats(); st.FilteredInbound != 1 || st.HairpinDelivered != 0 {
		t.Fatalf("%+v", st)
	}
}

func TestMultiExitPolicies(t *testing.T) {
	ips := []netip.Addr{netip.MustParseAddr("198.51.100.201"), netip.MustParseAddr("198.51.100.202"), netip.MustParseAddr("198.51.100.203")}
	t.Run("SingleExit", func(t *testing.T) {
		n := newNet(t)
		_, o := observer(t, n, 1)
		nat := n.NAT(NATConfig{ExternalIPs: ips})
		for i := range 4 {
			if m := srcAt(t, listen(t, nat.Host(), uint16(6000+i)), o); m.Addr() != ips[0] {
				t.Fatalf("exit %v", m)
			}
		}
	})
	t.Run("PerSourcePort", func(t *testing.T) {
		n := newNet(t)
		_, o1 := observer(t, n, 1)
		_, o2 := observer(t, n, 2)
		nat := n.NAT(NATConfig{ExternalIPs: ips, ExitPolicy: PerSourcePort})
		h := nat.Host()
		seen := map[netip.Addr]bool{}
		for i := range 16 {
			c := listen(t, h, uint16(6000+i))
			m1, m2 := srcAt(t, c, o1), srcAt(t, c, o2)
			if m1 != m2 {
				t.Fatalf("one socket, two exits: %v %v", m1, m2)
			}
			seen[m1.Addr()] = true
		}
		if len(seen) < 2 {
			t.Fatalf("no multi_exit evidence: %v", seen)
		}
	})
	t.Run("PerDestIP", func(t *testing.T) {
		n := newNet(t)
		nat := n.NAT(NATConfig{ExternalIPs: ips, ExitPolicy: PerDestIP})
		c := listen(t, nat.Host(), 6000)
		h1, o1 := observer(t, n, 1)
		o1b := listenOn(t, h1, "udp4", netip.AddrPortFrom(h1.Addrs()[0], 2))
		if srcAt(t, c, o1) != srcAt(t, c, o1b) {
			t.Fatal("the same destination IP must keep its mapping (EIM within one exit)")
		}
		seen := map[netip.Addr]bool{}
		for i := range 12 {
			_, o := observer(t, n, uint16(10+i))
			m := srcAt(t, c, o)
			if again := srcAt(t, c, o); again != m {
				t.Fatal("unstable per destination")
			}
			seen[m.Addr()] = true
		}
		if len(seen) < 2 {
			t.Fatalf("every destination used one exit: %v", seen)
		}
	})
	t.Run("RoundRobin", func(t *testing.T) {
		n := newNet(t)
		cfg := SymmetricSeq(1)
		cfg.ExternalIPs, cfg.ExitPolicy = ips, RoundRobin
		nat := n.NAT(cfg)
		c := listen(t, nat.Host(), 6000)
		for i := range 6 {
			_, o := observer(t, n, uint16(10+i))
			if got := srcAt(t, c, o).Addr(); got != ips[i%3] {
				t.Fatalf("mapping %d on %v, want %v", i, got, ips[i%3])
			}
		}
	})
}

func TestCGNAT(t *testing.T) {
	n := newNet(t)
	_, o := observer(t, n, 3478)
	cg := CGNAT(SymmetricSeq(1), PortRestricted())
	outer := n.NAT(cg[0])
	home := outer.NAT(cg[1])
	h := home.Host()
	c := listen(t, h, 4000)
	if e := ext(t, home); !netip.MustParsePrefix("100.64.0.0/10").Contains(e) {
		t.Fatalf("home external %v not in 100.64/10", e)
	}
	m := srcAt(t, c, o)
	if m.Addr() != ext(t, outer) {
		t.Fatalf("observer sees %v, want the carrier address %v", m, ext(t, outer))
	}
	hm, om := home.Mappings(), outer.Mappings()
	if len(hm) != 1 || len(om) != 1 || om[0].Internal != hm[0].External {
		t.Fatalf("two-level state:\nhome %+v\nouter %+v", hm, om)
	}
	send(t, o, m, "back")
	if s, src := recvNow(t, c); s != "back" || src != addrOf(o) {
		t.Fatalf("%q %v", s, src)
	}
	// Another subscriber of the carrier shares its public IP, not its port.
	other := listen(t, outer.NAT(FullCone()).Host(), 4000)
	if m2 := srcAt(t, other, o); m2.Addr() != m.Addr() || m2.Port() == m.Port() {
		t.Fatalf("second subscriber %v vs %v", m2, m)
	}
	if hp := h.publicAddr(); hp != m.Addr() {
		t.Fatalf("publicAddr %v", hp)
	}
	if c := CGNAT(NATConfig{}, NATConfig{}); c[0].Name != "CGNAT" || c[1].Name != "" {
		t.Fatalf("unnamed carrier %+v", c)
	}
}

// TestNATBehindFirewall nests a translating NAT inside a PUBFW network: its
// external address is public and reaches it through the firewall state, and
// Rebind re-registers it on every level.
func TestNATBehindFirewall(t *testing.T) {
	n := newNet(t)
	_, o := observer(t, n, 1)
	fw := n.NAT(PublicFW())
	inner := fw.NAT(PortRestricted())
	c := listen(t, inner.Host(), 4000)
	m := srcAt(t, c, o)
	if m.Addr() != ext(t, inner) || m.Addr().IsPrivate() {
		t.Fatalf("mapping %v", m)
	}
	send(t, o, m, "back")
	recvNow(t, c)
	if len(fw.Mappings()) != 1 || len(inner.Mappings()) != 1 {
		t.Fatal("state on both levels expected")
	}
	old := m.Addr()
	inner.Rebind(nil)
	if n.lookup(n.core, old) != nil || n.lookup(fw.lan, old) != nil {
		t.Fatal("the old address is still registered")
	}
	m2 := srcAt(t, c, o)
	send(t, o, m2, "back")
	recvNow(t, c)
}

// TestPipeAddressesThroughNATs: a pipe end reports what a TCP server on the
// core would see.
func TestPipeAddressesThroughNATs(t *testing.T) {
	n := newNet(t)
	srv := n.PublicHost()
	nat := n.NAT(SymmetricSeq(1))
	a, b := n.Pipe(PipeConfig{A: nat.Host(), B: srv})
	if ra := b.RemoteAddr().(*net.TCPAddr).AddrPort().Addr(); ra != ext(t, nat) {
		t.Fatalf("server sees %v, want %v", ra, ext(t, nat))
	}
	if la := b.LocalAddr().(*net.TCPAddr).AddrPort().Addr(); la != srv.Addrs()[0] {
		t.Fatalf("server local %v", la)
	}
	if a.LocalAddr().String() != b.RemoteAddr().String() {
		t.Fatal("the ends disagree")
	}
	c, _ := n.Pipe(PipeConfig{})
	if !c.LocalAddr().(*net.TCPAddr).AddrPort().Addr().IsLoopback() {
		t.Fatalf("hostless end %v", c.LocalAddr())
	}
}

func TestTTL(t *testing.T) {
	setup := func(t *testing.T) (*Network, *NAT, *NAT, udp, udp, netip.AddrPort, netip.AddrPort) {
		n := newNet(t) // the core counts as 8 hops
		_, o := observer(t, n, 3478)
		na, nb := n.NAT(PortRestricted()), n.NAT(PortRestricted())
		a, b := listen(t, na.Host(), 4000), listen(t, nb.Host(), 4000)
		ma, mb := srcAt(t, a, o), srcAt(t, b, o)
		return n, na, nb, a, b, ma, mb
	}
	t.Run("LowTTLOpensOnlyTheLocalNAT", func(t *testing.T) {
		n, na, nb, a, b, ma, mb := setup(t)
		for _, hops := range []int{4, 7} {
			_ = a.SetHopLimit(hops)
			send(t, a, mb, "low")
		}
		if st := n.Stats(); st.Dropped.TTL != 2 {
			t.Fatalf("core TTL drops %d", st.Dropped.TTL)
		}
		if st := nb.Stats(); st.FilteredInbound != 0 {
			t.Fatal("a low-TTL packet reached the peer NAT")
		}
		// A's NAT now permits B: B's normal packet gets in.
		_ = a.SetHopLimit(0)
		send(t, b, ma, "normal")
		if s, _ := recvNow(t, a); s != "normal" {
			t.Fatal(s)
		}
		if mi := na.Mappings(); len(mi[0].Permits) != 2 {
			t.Fatalf("permits %v", mi[0].Permits)
		}
	})
	t.Run("TTL1DiesAtTheFirstRouterWithoutState", func(t *testing.T) {
		_, na, _, a, b, ma, mb := setup(t)
		_ = a.SetHopLimit(1)
		send(t, a, mb, "ttl1")
		if st := na.Stats(); st.Dropped.TTL != 1 {
			t.Fatalf("%+v", st.Dropped)
		}
		send(t, b, ma, "x")
		expectNone(t, a)
	})
	t.Run("ExactlyEnough", func(t *testing.T) {
		// NAT A (1 router) + core (8) + NAT B (1): TTL 11 reaches B's
		// filter, 10 arrives at NAT B with TTL 1 and dies there, 9 dies in
		// the core.
		n, _, nb, a, _, _, mb := setup(t)
		_ = a.SetHopLimit(11)
		send(t, a, mb, "11")
		if st := nb.Stats(); st.FilteredInbound != 1 {
			t.Fatalf("TTL 11 did not reach NAT B's filter: %+v", st)
		}
		_ = a.SetHopLimit(10)
		send(t, a, mb, "10")
		if st := nb.Stats(); st.Dropped.TTL != 1 || st.FilteredInbound != 1 {
			t.Fatalf("TTL 10: %+v", st)
		}
		_ = a.SetHopLimit(9)
		send(t, a, mb, "9")
		if st := n.Stats(); st.Dropped.TTL != 2 { // NAT B's drop and the core's
			t.Fatalf("%+v", st.Dropped)
		}
	})
	t.Run("CGNATHops", func(t *testing.T) {
		n := newNet(t)
		_, o := observer(t, n, 3478)
		cg := CGNAT(PortRestricted(), PortRestricted())
		outer := n.NAT(cg[0])
		home := outer.NAT(cg[1])
		c := listen(t, home.Host(), 4000)
		_ = c.SetHopLimit(2) // crosses the home NAT, dies at the carrier
		send(t, c, addrOf(o), "x")
		if len(home.Mappings()) != 1 || len(outer.Mappings()) != 0 || outer.Stats().Dropped.TTL != 1 {
			t.Fatalf("home %v outer %v", home.Mappings(), outer.Mappings())
		}
	})
}

func TestWithCoreHops(t *testing.T) {
	n := newNet(t, WithCoreHops(1), WithCoreHops(-3))
	_, o := observer(t, n, 3478)
	c := listen(t, n.NAT(FullCone()).Host(), 4000)
	_ = c.SetHopLimit(3) // the NAT leaves 2, the one-router core needs more than 1
	send(t, c, addrOf(o), "x")
	recvNow(t, o)
}

func TestAddressPlan(t *testing.T) {
	if p := publicV4(254*3 + 5); p != netip.MustParseAddr("198.18.0.6") {
		t.Fatal(p)
	}
	if p := publicV4(0); p != netip.MustParseAddr("203.0.113.1") {
		t.Fatal(p)
	}
	n := newNet(t)
	nat := n.NAT(NATConfig{LANPrefix: netip.MustParsePrefix("192.168.7.0/30")})
	for range 3 { // .1, .2 and .3
		nat.Host()
	}
	mustPanic(t, "exhausted LAN", func() { nat.Host() })
}

func TestStaticConfigErrors(t *testing.T) {
	n := newNet(t)
	srv := n.PublicHost(netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("2001:db8:ffff::1"))
	nat := n.NAT(NATConfig{ExternalIPs: []netip.Addr{netip.MustParseAddr("5.6.7.8")}, LANPrefix: netip.MustParsePrefix("192.168.1.0/24")})
	h := nat.Host(netip.MustParseAddr("192.168.1.10"))
	if auto := nat.Host(); !netip.MustParsePrefix("192.168.1.0/24").Contains(auto.Addrs()[0]) {
		t.Fatalf("automatic LAN address %v", auto.Addrs())
	}
	o := listenOn(t, srv, "udp4", netip.MustParseAddrPort("1.2.3.4:53"))
	if m := srcAt(t, listen(t, h, 4000), o); m != netip.MustParseAddrPort("5.6.7.8:4000") {
		t.Fatal(m)
	}
	mustPanic(t, "duplicate public address", func() { n.PublicHost(netip.MustParseAddr("1.2.3.4")) })
	mustPanic(t, "duplicate LAN address", func() { nat.Host(netip.MustParseAddr("192.168.1.10")) })
	mustPanic(t, "duplicate external address", func() { n.NAT(NATConfig{ExternalIPs: []netip.Addr{netip.MustParseAddr("5.6.7.8")}}) })
	mustPanic(t, "missing family", func() { nat.Host(netip.MustParseAddr("fd00::1")) })
	mustPanic(t, "no address", func() { nat.Host(netip.IPv6Unspecified()) })
	mustPanic(t, "IPv6 under an IPv4-only NAT", func() { nat.NAT(NATConfig{IPv6: &IPv6Config{Mode: NAT66}}) })
	mustPanic(t, "nested NPTv6", func() {
		n.NAT(NATConfig{IPv6: &IPv6Config{Mode: NAT66}}).NAT(NATConfig{IPv6: &IPv6Config{Mode: NPTv6}})
	})
	mustPanic(t, "rebind onto a used address", func() { nat.Rebind([]netip.Addr{netip.MustParseAddr("1.2.3.4")}) })
}

func TestNATNames(t *testing.T) {
	n := newNet(t)
	a, b, c := n.NAT(FullCone()), n.NAT(FullCone()), n.NAT(NATConfig{})
	if a.name != "FC" || b.name != "FC#2" || c.name != "nat3" {
		t.Fatal(a.name, b.name, c.name)
	}
	if h := a.Host(); h.name != "FC.h1" || n.PublicHost().name != "pub2" {
		t.Fatal("host names")
	}
}

func TestPresets(t *testing.T) {
	for _, tc := range []struct {
		cfg   NATConfig
		name  string
		m     Mapping
		f     Filtering
		alloc PortAlloc
	}{
		{PublicOpen(), "PUB", Identity, Open, Preserve},
		{PublicFW(), "PUBFW", Identity, APDF, Preserve},
		{FullCone(), "FC", EIM, EIF, Preserve},
		{RestrictedCone(), "RC", EIM, ADF, Preserve},
		{PortRestricted(), "PRC", EIM, APDF, Preserve},
		{SymmetricSeq(2), "SYMSEQ2", APDM, APDF, Sequential},
		{SymmetricSeq(-1), "SYMSEQ-1", APDM, APDF, Sequential},
		{SymmetricRandom(), "SYMRND", APDM, APDF, Random},
		{SymmetricPreserveRandom(), "PRESRND", APDM, APDF, PreserveThenRandom},
	} {
		c := tc.cfg
		if c.Name != tc.name || c.Mapping != tc.m || c.Filtering != tc.f || c.PortAlloc != tc.alloc || c.IPv6 != nil {
			t.Errorf("%s: %+v", tc.name, c)
		}
	}
	if SymmetricSeq(2).PortStep != 2 {
		t.Error("SymmetricSeq step")
	}
	n := newNet(t)
	_, o := observer(t, n, 1)
	rc := n.NAT(RestrictedCone())
	m := srcAt(t, listen(t, rc.Host(), 4000), o)
	if m.Port() != 4000 {
		t.Fatalf("RC does not preserve the port: %v", m)
	}
}
