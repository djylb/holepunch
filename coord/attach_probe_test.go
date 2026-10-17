package coord

import (
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/djylb/holepunch/coord/internal/simclient"
	"github.com/djylb/holepunch/protocol"
)

// TestAttachProbe: AttachOptions.Probe replaces the role's ProbeSpec in the
// punch_start written on its stream, and PunchStart reports it; one that
// makes punch_start invalid is refused with the stream untouched.
func TestAttachProbe(t *testing.T) {
	r := newRig(t)
	s := r.session(SessionOptions{})
	spec := protocol.ProbeSpec{Observers: []protocol.ObserverSpec{{ID: 1, Addr: netip.MustParseAddrPort("198.51.100.7:3478")}}}
	srv, cli := net.Pipe()
	if err := s.Attach(protocol.RoleInitiator, srv, AttachOptions{Security: protocol.ControlSecurityInsecureForTesting, Probe: &spec}); err != nil {
		t.Fatal(err)
	}
	c, err := simclient.New(cli, protocol.RoleInitiator, simclient.Options{Now: r.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	start := expect[protocol.PunchStart](t, c)
	if !slices.Equal(start.Probe.Observers, spec.Observers) {
		t.Fatalf("punch_start observers %v, want %v", start.Probe.Observers, spec.Observers)
	}
	if got := s.PunchStart(protocol.RoleInitiator).Probe.Observers; !slices.Equal(got, spec.Observers) {
		t.Fatalf("PunchStart observers %v", got)
	}

	bad := protocol.ProbeSpec{Observers: []protocol.ObserverSpec{{ID: 1}}} // no address
	srv2, cli2 := net.Pipe()
	defer func() { _ = srv2.Close(); _ = cli2.Close() }()
	if err := s.Attach(protocol.RoleResponder, srv2, AttachOptions{Security: protocol.ControlSecurityInsecureForTesting, Probe: &bad}); !invalidArgument(err) {
		t.Fatalf("invalid probe: %v", err)
	}
}
