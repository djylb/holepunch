package natprobe

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/djylb/holepunch/protocol"
)

// An optional group whose sockets cannot be bound is closed and skipped; the
// others start.
func TestServerOptionalGroup(t *testing.T) {
	var opened, closed atomic.Int32
	v6calls := 0
	// IPv6 fails on its second socket, so that one is opened and must be
	// closed again.
	listen := func(network string, laddr netip.AddrPort) (net.PacketConn, error) {
		if network == "udp6" {
			if v6calls++; v6calls > 1 {
				return nil, errors.New("injected: no IPv6")
			}
			laddr = netip.AddrPortFrom(lo4, 0)
			network = "udp4"
		}
		c, err := defaultListen(network, laddr)
		if err != nil {
			return nil, err
		}
		opened.Add(1)
		return &closeCounter{PacketConn: c, n: &closed}, nil
	}
	v6 := netip.MustParseAddr("2001:db8::1")
	s := startServer(t, ServerConfig{Listen: listen, Groups: []ObserverGroup{
		{Bind: lo4},
		{Bind: netip.IPv6Unspecified(), Advertise: []netip.Addr{v6}, Slots: 2, Optional: true},
	}})
	if st := s.Stats(); st.SkippedGroups != 1 {
		t.Fatalf("SkippedGroups %d", st.SkippedGroups)
	}
	if closed.Load() != 1 {
		t.Fatalf("the skipped group's socket was not closed: %d closed", closed.Load())
	}
	if obs := s.Observers(protocol.FamilyUDP6); obs != nil {
		t.Fatalf("observers of the skipped group: %+v", obs)
	}
	spec := s.ProbeSpecAt(netip.MustParseAddr("2001:db8::2"))
	if len(spec.Observers) != 3 {
		t.Fatalf("spec %+v", spec.Observers)
	}
	for _, o := range spec.Observers {
		if !o.Addr.Addr().Is4() {
			t.Fatalf("observer %+v of the skipped group", o)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if closed.Load() != opened.Load() {
		t.Fatalf("opened %d closed %d", opened.Load(), closed.Load())
	}
}

// Optional groups cannot leave the server without a non-alt group; a group
// that is not optional still fails Start.
func TestServerOptionalGroupNoneStarted(t *testing.T) {
	fail6 := func(network string, laddr netip.AddrPort) (net.PacketConn, error) {
		if network == "udp6" {
			return nil, errors.New("injected: no IPv6")
		}
		return defaultListen(network, laddr)
	}
	for _, tc := range []struct {
		name   string
		groups []ObserverGroup
		want   string
	}{
		{"all optional", []ObserverGroup{{Bind: netip.IPv6Loopback(), Optional: true}}, "no non-alt group started"},
		{"only an alt started", []ObserverGroup{{Bind: netip.IPv6Loopback(), Optional: true}, {Bind: lo4, Alt: true}}, "no non-alt group started"},
		{"required", []ObserverGroup{{Bind: lo4}, {Bind: netip.IPv6Loopback()}}, "injected"},
	} {
		s, err := NewServer(ServerConfig{Registry: NewRegistry(RegistryConfig{}), Groups: tc.groups, Listen: fail6})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Start(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: %v", tc.name, err)
		}
		_ = s.Close()
	}
}
