package holepunch

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"testing"

	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/portmapper"
	"github.com/djylb/holepunch/protocol"
)

// Android 11 and later refuse the interface list to ordinary apps. The
// session then runs without LAN addresses, still connects, and says so in
// Diagnostics.Warn and punch_result.warn; a panicking InterfaceAddrs is the
// same failure.
func TestInterfaceListUnavailable(t *testing.T) {
	t.Parallel()
	for _, panics := range []bool{false, true} {
		t.Run(map[bool]string{false: "error", true: "panic"}[panics], func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			ps := &pairScript{w: w, timeouts: testTimeouts()}
			pr := runPair(t, w, [2]*nattest.NATConfig{prc(), prc()}, ps, func(_ int, o *Options) {
				o.Network = noInterfacesNetwork{Network: o.Network, panics: panics}
			})
			defer pr.closeAll()
			wantSuccess(t, pr)
			for i := range 2 {
				d := pr.res[i].sess.Diagnostics()
				if !slices.Contains(d.Warn, protocol.WarnInterfaceListUnavailable) {
					t.Fatalf("client %d: warn %v", i, d.Warn)
				}
				if panics != (d.Counters.CallbackPanics > 0) {
					t.Fatalf("client %d: %d callback panics", i, d.Counters.CallbackPanics)
				}
				if r := ps.results[i]; r == nil || !slices.Contains(r.Warn, protocol.WarnInterfaceListUnavailable) {
					t.Fatalf("client %d: punch_result %+v", i, r)
				}
			}
		})
	}
}

// An unresolvable LocalInterface (Android refuses the interface table; or
// the name does not exist) leaves the session without a preference and
// with the same warning; an interface the Network lists by name
// gives its addresses.
func TestLocalInterfaceUnavailable(t *testing.T) {
	t.Parallel()
	_, h := simHost(t)
	for _, c := range []struct {
		name  string
		netw  Network
		iface string
		want  int
	}{
		{"missing", h, "holepunch-no-such-if", 0},
		{"refused", noInterfacesNetwork{Network: h}, "eth0", 0},
		{"listed", h, "eth0", 1},
	} {
		rt := newTestRuntime(t, fakeClock(t), c.netw)
		rt.opts.LocalInterface = c.iface
		rt.readHosts()
		if len(rt.ifacePrefer) != c.want || slices.Contains(rt.warnings(), protocol.WarnInterfaceListUnavailable) == (c.want > 0) {
			t.Fatalf("%s: preference %v, warn %v", c.name, rt.ifacePrefer, rt.warnings())
		}
	}
}

// noInterfacesNetwork fails InterfaceAddrs the way Android does (netlink
// permission denied), or panics.
type noInterfacesNetwork struct {
	Network
	panics bool
}

func (n noInterfacesNetwork) InterfaceAddrs() ([]net.Interface, [][]netip.Prefix, error) {
	if n.panics {
		panic("interface list")
	}
	return nil, nil, &net.OpError{Op: "route", Net: "ip+net", Err: os.NewSyscallError("netlinkrib", fs.ErrPermission)}
}

// Without a default gateway — Android may refuse /proc/net/route too — the
// port mapper fails with ErrNoGateway, and only port mapping is off: the
// session punches as usual.
func TestPortMapperWithoutGateway(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	ps := &pairScript{w: w, timeouts: testTimeouts()}
	var maps [2]*mapErrors
	pr := runPair(t, w, [2]*nattest.NATConfig{prc(), prc()}, ps, func(i int, o *Options) {
		m := portmapper.New(portmapper.Config{
			Network: o.Network,
			Gateway: func(context.Context) (netip.Addr, error) {
				return netip.Addr{}, &fs.PathError{Op: "open", Path: "/proc/net/route", Err: fs.ErrPermission}
			},
		})
		t.Cleanup(func() { _ = m.Close() })
		maps[i] = &mapErrors{m: m}
		o.PortMapper = maps[i]
	})
	defer pr.closeAll()
	wantSuccess(t, pr)
	for i := range 2 {
		errs := maps[i].all()
		if len(errs) == 0 {
			t.Fatalf("client %d: no mapping attempted", i)
		}
		for _, err := range errs {
			if !errors.Is(err, portmapper.ErrNoGateway) {
				t.Fatalf("client %d: Map error %v, want ErrNoGateway", i, err)
			}
		}
		if res := pr.res[i].sess.Result(); res.Path.PortMapping != nil {
			t.Fatalf("client %d: mapping %+v", i, res.Path.PortMapping)
		}
	}
}

// mapErrors is a PortMapper that records the errors of a real Mapper.
type mapErrors struct {
	m    *portmapper.Mapper
	mu   sync.Mutex
	errs []error
}

func (r *mapErrors) Map(ctx context.Context, conn net.PacketConn, p protocol.PortMappingPolicy) (protocol.PortMappingInfo, func() error, error) {
	info, release, err := r.m.Map(ctx, conn, p)
	r.mu.Lock()
	r.errs = append(r.errs, err)
	r.mu.Unlock()
	return info, release, err
}

func (r *mapErrors) all() []error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.errs)
}

// The library binds every socket for one family, "udp4" or "udp6", and
// never asks for a dual-stack one, so no platform's IPV6_V6ONLY default can
// change what a socket receives.
func TestSocketsPerFamily(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	ps := &pairScript{w: w, timeouts: testTimeouts()}
	var nets [2]*familyLog
	pr := runPair(t, w, [2]*nattest.NATConfig{prc(), prc()}, ps, func(i int, o *Options) {
		nets[i] = &familyLog{Network: o.Network}
		o.Network = nets[i]
	})
	defer pr.closeAll()
	wantSuccess(t, pr)
	for i := range 2 {
		got := nets[i].all()
		if len(got) == 0 {
			t.Fatalf("client %d opened no socket", i)
		}
		for _, n := range got {
			if n != string(protocol.FamilyUDP4) && n != string(protocol.FamilyUDP6) {
				t.Fatalf("client %d asked for a %q socket", i, n)
			}
		}
	}
}

// familyLog records the network of every ListenPacket.
type familyLog struct {
	Network
	mu   sync.Mutex
	nets []string
}

func (l *familyLog) ListenPacket(ctx context.Context, network string, laddr netip.AddrPort, purpose string) (net.PacketConn, error) {
	l.mu.Lock()
	l.nets = append(l.nets, network)
	l.mu.Unlock()
	return l.Network.ListenPacket(ctx, network, laddr, purpose)
}

func (l *familyLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.nets)
}

// uncomparableNetwork returns its sockets as values of a type == cannot
// compare, which a Network may do.
type uncomparableNetwork struct{ Network }

func (n uncomparableNetwork) ListenPacket(ctx context.Context, network string, laddr netip.AddrPort, purpose string) (net.PacketConn, error) {
	c, err := n.Network.ListenPacket(ctx, network, laddr, purpose)
	if err != nil {
		return nil, err
	}
	return uncomparableConn{PacketConn: c}, nil
}

// Whatever its sockets' type, a session hands over open sockets: the
// session group tells them apart by identity, not by comparing the conns.
func TestUncomparableConnsHandedOpen(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	ps := &pairScript{w: w, timeouts: testTimeouts()}
	pr := runPair(t, w, [2]*nattest.NATConfig{prc(), prc()}, ps, func(_ int, o *Options) {
		o.Network = uncomparableNetwork{o.Network}
	})
	defer pr.closeAll()
	for i, r := range pr.res {
		if r.err != nil {
			t.Fatalf("client %d: %v", i, r.err)
		}
		to := net.UDPAddrFromAddrPort(r.sess.Result().Path.RemoteAddr)
		if _, err := r.sess.PacketConn().WriteTo([]byte("x"), to); errors.Is(err, net.ErrClosed) {
			t.Fatalf("client %d: handed over a closed socket", i)
		}
	}
}
