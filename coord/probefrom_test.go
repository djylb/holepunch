package coord

import (
	"net/netip"
	"testing"

	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/protocol"
)

func TestProbeFrom(t *testing.T) {
	srv, err := natprobe.NewServer(natprobe.ServerConfig{Registry: natprobe.NewRegistry(natprobe.RegistryConfig{}),
		Groups: []natprobe.ObserverGroup{{Bind: netip.IPv4Unspecified(), Slots: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()
	addrs := natprobe.NewServerAddrs(natprobe.ServerAddrsConfig{Public: []netip.Addr{netip.MustParseAddr("203.0.113.1")}})
	spec, err := ProbeFrom(natprobe.SpecSource{Server: srv, Addrs: addrs})(protocol.RoleInitiator, &SessionOptions{})
	if err != nil || len(spec.Observers) != 3 || spec.Observers[0].Addr.Addr() != netip.MustParseAddr("203.0.113.1") {
		t.Fatalf("%+v, %v", spec, err)
	}
}
