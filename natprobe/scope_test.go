package natprobe

import (
	"net"
	"net/netip"
	"testing"

	"github.com/djylb/holepunch/protocol"
)

// TestGroupValidation: the address list of a group is checked as a whole.
func TestGroupValidation(t *testing.T) {
	a, b := netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("198.51.100.2")
	for name, g := range map[string]ObserverGroup{
		"unknown scope":            {Bind: lo4, Scope: 9},
		"repeated address":         {Bind: lo4, Advertise: []netip.Addr{a, a}},
		"too few slots":            {Bind: lo4, Advertise: []netip.Addr{a, b}, Slots: 1},
		"wildcard alt":             {Bind: netip.IPv4Unspecified(), Alt: true},
		"alt slots":                {Bind: lo4, Alt: true, Slots: 2},
		"address of another group": {Bind: netip.MustParseAddr("127.0.0.3"), Advertise: []netip.Addr{lo4}},
	} {
		groups := []ObserverGroup{{Bind: lo4}, g}
		if g.Alt {
			groups[0].Bind = netip.MustParseAddr("127.0.0.2")
		}
		if _, err := NewServer(ServerConfig{Registry: NewRegistry(RegistryConfig{}), Groups: groups}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Every address slot is PortCount observers: 3 × 6 > 16 of a family.
	if _, err := NewServer(ServerConfig{Registry: NewRegistry(RegistryConfig{}), Groups: []ObserverGroup{{Bind: lo4, Slots: 3}}, PortCount: 6}); err == nil {
		t.Error("18 observers of a family accepted")
	}
}

// A wildcard group announces at each session's addresses: ProbeSpec has
// only its Advertise, ProbeSpecAt fills the free slots in order, one
// observer group per address at the same ports, without repeats.
func TestProbeSpecAt(t *testing.T) {
	s := startServer(t, ServerConfig{Groups: []ObserverGroup{{Bind: netip.IPv4Unspecified(), Slots: 2}}})
	if spec := s.ProbeSpec(); len(spec.Observers) != 0 {
		t.Fatalf("observers without an address: %v", spec.Observers)
	}
	pub, lan := netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("192.168.7.1")
	spec := s.ProbeSpecAt(pub, pub, netip.MustParseAddr("2001:db8::1"), lan, netip.MustParseAddr("198.51.100.3"))
	if len(spec.Observers) != 2*s.cfg.PortCount {
		t.Fatalf("%d observers: %v", len(spec.Observers), spec.Observers)
	}
	ports := map[uint16]bool{}
	for _, o := range spec.Observers {
		og, pi := int(o.ID)/portsPerGroup, int(o.ID)%portsPerGroup
		want := []netip.Addr{pub, lan}[og]
		if int(o.Group) != og || o.Addr.Addr() != want || o.Addr.Port() != s.listeners[pi].port {
			t.Fatalf("observer %+v: want %v at listener %d's port", o, want, pi)
		}
		ports[o.Addr.Port()] = true
	}
	if len(ports) != s.cfg.PortCount {
		t.Fatalf("the two addresses use %d ports, want the same %d", len(ports), s.cfg.PortCount)
	}

	// An address is announced once per family: one a group already
	// advertises does not fill another group's slot.
	two := startServer(t, ServerConfig{Groups: []ObserverGroup{{Bind: lo4}, {Bind: netip.IPv4Unspecified(), Slots: 2}}})
	for _, o := range two.ProbeSpecAt(lo4, pub).Observers {
		if o.Group != 0 && o.Addr.Addr() == lo4 {
			t.Fatalf("%v announced twice: %v", lo4, o)
		}
	}

	fixed := startServer(t, ServerConfig{Groups: []ObserverGroup{{Bind: lo4, Slots: 2}}})
	if got := fixed.ProbeSpecAt(lo4, lan).Observers; len(got) != 2*fixed.cfg.PortCount || got[len(got)-1].Addr.Addr() != lan {
		t.Fatalf("Advertise then one more: %v", got)
	}
}

// A listener serves one observer id per address slot, at its port index.
func TestListenerServes(t *testing.T) {
	l := &listener{og: 2, slots: 2, pi: 1}
	for aux, want := range map[uint16]bool{17: true, 25: true, 16: false, 18: false, 33: false, 9: false} {
		if l.serves(aux) != want {
			t.Errorf("serves(%d) = %v", aux, !want)
		}
	}
}

// The scope of an observation: a group's forced Scope, else the address
// the observer was announced at in the session.
func TestObservationScope(t *testing.T) {
	h := &handle{e: &entry{}}
	h.Announce(protocol.RoleResponder, []protocol.ObserverSpec{
		{ID: 0, Addr: netip.MustParseAddrPort("192.168.7.1:3478")},
		{ID: 8, Addr: netip.MustParseAddrPort("203.0.113.9:3478")},
	})
	r := &h.e.roles[1]
	for _, c := range []struct {
		obs, flags uint8
		lan        bool
	}{
		{0, 0, true}, {8, 0, false}, {0, slotPublic, false}, {8, slotPrivate, true}, {16, 0, false},
	} {
		if got := r.lan(slot{obs: c.obs, flags: c.flags}); got != c.lan {
			t.Errorf("observer %d flags %b: LAN %v", c.obs, c.flags, got)
		}
	}
	// A free slot's observer, never announced, is refused.
	if r.unannounced(0) || r.unannounced(8) || !r.unannounced(16) {
		t.Error("announced observers")
	}
	if (&roleState{}).unannounced(16) {
		t.Error("a role nothing was announced to refuses observers")
	}
}

// TestWildcardRepliesFromProbedAddress: a wildcard group with two address
// slots answers each address's observers, the ack and the extra reply both
// from the address the probe was sent to — 127.0.0.2 as well where the
// loopback interface has it (Linux), not the address the system routes the
// client by.
func TestWildcardRepliesFromProbedAddress(t *testing.T) {
	reg := NewRegistry(RegistryConfig{})
	s := startServer(t, ServerConfig{Registry: reg, Groups: []ObserverGroup{{Bind: netip.IPv4Unspecified(), Slots: 2}}})
	addrs := []netip.Addr{lo4}
	if c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.2:0"))); err == nil {
		_ = c.Close()
		addrs = append(addrs, netip.MustParseAddr("127.0.0.2"))
	}
	spec := s.ProbeSpecAt(addrs...)
	h := register(t, reg, "s1", tok(1), rt(1))
	h.Announce(protocol.RoleInitiator, spec.Observers)
	c := newUDPClient(t, tok(1), rt(1))
	for _, o := range spec.Observers {
		if o.ID%portsPerGroup != 0 {
			continue
		}
		reps := c.exchange(o.Addr, probeOpts{obs: o.ID, extra: true}, 2)
		if len(reps) != 2 {
			t.Fatalf("observer %d at %v: %d replies", o.ID, o.Addr, len(reps))
		}
		for _, r := range reps {
			if r.from.Addr() != o.Addr.Addr() {
				t.Fatalf("observer %d at %v: a reply from %v", o.ID, o.Addr, r.from)
			}
		}
	}
	t.Logf("addresses %v; destination reports: %v", addrs, s.listeners[0].msg != nil)
}
