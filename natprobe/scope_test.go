package natprobe

import (
	"net/netip"
	"testing"
)

// A wildcard group may leave Advertise to each session when it names its
// Scope: ProbeSpec carries its observers without an address, ProbeSpecAt
// fills them in at their ports, and the Scope marks the slots.
func TestWildcardScope(t *testing.T) {
	if _, err := NewServer(ServerConfig{Registry: NewRegistry(RegistryConfig{}), Groups: []ObserverGroup{{Bind: netip.IPv4Unspecified()}}}); err == nil {
		t.Fatal("a wildcard group without Advertise or Scope accepted")
	}
	if _, err := NewServer(ServerConfig{Registry: NewRegistry(RegistryConfig{}), Groups: []ObserverGroup{{Bind: lo4, Scope: 9}}}); err == nil {
		t.Fatal("an unknown Scope accepted")
	}
	s := startServer(t, ServerConfig{Groups: []ObserverGroup{{Bind: netip.IPv4Unspecified(), Scope: ScopePrivate}}})
	spec := s.ProbeSpec()
	if len(spec.Observers) == 0 {
		t.Fatal("no observers")
	}
	for _, o := range spec.Observers {
		if o.Addr.Addr().IsValid() || o.Addr.Port() == 0 {
			t.Fatalf("observer %+v: want no address, a port", o)
		}
	}
	at := netip.MustParseAddr("192.168.7.1")
	got := s.ProbeSpecAt(at, netip.MustParseAddr("2001:db8::1"))
	if len(got.Observers) != len(spec.Observers) {
		t.Fatalf("ProbeSpecAt kept %d of %d observers", len(got.Observers), len(spec.Observers))
	}
	for i, o := range got.Observers {
		if o.Addr != netip.AddrPortFrom(at, spec.Observers[i].Addr.Port()) || o.ID != spec.Observers[i].ID {
			t.Fatalf("observer %+v, want %v at port %d", o, at, spec.Observers[i].Addr.Port())
		}
	}
	if got := s.ProbeSpecAt(netip.MustParseAddr("2001:db8::1")); len(got.Observers) != 0 {
		t.Fatalf("observers without an address of their family kept: %v", got.Observers)
	}
	for _, l := range s.listeners {
		if l.flags&slotPrivate == 0 {
			t.Fatalf("listener %d not marked private", l.id)
		}
	}
	// ScopePublic overrides a private Advertise.
	pub := startServer(t, ServerConfig{Groups: []ObserverGroup{{Bind: lo4, Scope: ScopePublic}}})
	for _, l := range pub.listeners {
		if l.flags&slotPrivate != 0 {
			t.Fatalf("listener %d of a public group marked private", l.id)
		}
	}
}
