package holepunch_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/djylb/holepunch"
	"github.com/djylb/holepunch/coord"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

// The coordinator runs in process with the clients: each control stream is
// a net.Pipe, attached before Punch reads its end, as the README shows.
func TestEmbeddedCoordinatorPipe(t *testing.T) {
	n := nattest.NewNetwork(nattest.WithSeed(1))
	defer func() { _ = n.Close() }()
	server := n.PublicHost(netip.IPv4Unspecified())
	hosts := [2]*nattest.Host{n.NAT(nattest.PortRestricted()).Host(), n.NAT(nattest.PortRestricted()).Host()}
	reg := natprobe.NewRegistry(natprobe.RegistryConfig{})
	probe, err := natprobe.NewServer(natprobe.ServerConfig{Registry: reg, Groups: []natprobe.ObserverGroup{{Bind: server.Addrs()[0]}}, Listen: server.Listen})
	if err != nil {
		t.Fatal(err)
	}
	if err := probe.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = probe.Close() }()
	co, err := coord.New(coord.Config{Registry: reg, Probe: coord.ProbeFrom(natprobe.SpecSource{Server: probe})})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = co.Close() }()
	sess, err := co.NewSession(coord.SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var wg sync.WaitGroup
	var sessions [2]*holepunch.Session
	var errs [2]error
	var ends [2]net.Conn
	defer func() {
		for _, c := range ends {
			if c != nil {
				_ = c.Close()
			}
		}
	}()
	for i, role := range []protocol.Role{protocol.RoleInitiator, protocol.RoleResponder} {
		clientEnd, coordEnd := net.Pipe()
		ends[i] = clientEnd
		if err := sess.Attach(role, coordEnd, coord.AttachOptions{Security: protocol.ControlSecurityDeclared}); err != nil {
			t.Fatal(err)
		}
		wg.Go(func() {
			sessions[i], errs[i] = holepunch.Punch(ctx, clientEnd, holepunch.Options{ControlSecurity: protocol.ControlSecurityDeclared, Network: hosts[i]})
		})
	}
	wg.Wait()
	for _, s := range sessions {
		if s != nil {
			_ = s.Close()
		}
	}
	if err := errors.Join(errs[:]...); err != nil {
		t.Fatal(err)
	}
}
