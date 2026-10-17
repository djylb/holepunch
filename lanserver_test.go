package holepunch_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/djylb/holepunch"
	"github.com/djylb/holepunch/coord"
	"github.com/djylb/holepunch/internal/plan"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/stun"
)

// lanServerAddr is the server's public address. The server also sits in the
// router's LAN at the same address, so clients in that LAN reach it without
// translation: what a LAN route to the server's public IP, or a router
// hairpin that keeps the source address, does.
var lanServerAddr = netip.MustParseAddr("198.19.255.250")

// dualConn is one server socket bound at the same address in the core and
// in the router's LAN; it answers each client on the side it came from.
type dualConn struct {
	lan, core net.PacketConn
	prefix    netip.Prefix // the router's LAN
	in        chan dgram
	done      chan struct{}
	once      sync.Once
	wg        sync.WaitGroup
}

type dgram struct {
	b    []byte
	from net.Addr
}

func newDualConn(lan, core net.PacketConn, prefix netip.Prefix) *dualConn {
	d := &dualConn{lan: lan, core: core, prefix: prefix, in: make(chan dgram, 1024), done: make(chan struct{})}
	for _, c := range []net.PacketConn{lan, core} {
		d.wg.Go(func() {
			buf := make([]byte, 2048)
			for {
				n, from, err := c.ReadFrom(buf)
				if err != nil {
					return
				}
				select {
				case d.in <- dgram{append([]byte(nil), buf[:n]...), from}:
				case <-d.done:
					return
				}
			}
		})
	}
	return d
}

func (d *dualConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case g := <-d.in:
		return copy(b, g.b), g.from, nil
	case <-d.done:
		return 0, nil, net.ErrClosed
	}
}

func (d *dualConn) WriteTo(b []byte, to net.Addr) (int, error) {
	if ua, ok := to.(*net.UDPAddr); ok && d.prefix.Contains(ua.AddrPort().Addr().Unmap()) {
		return d.lan.WriteTo(b, to)
	}
	return d.core.WriteTo(b, to)
}

func (d *dualConn) Close() error {
	d.once.Do(func() {
		close(d.done)
		_, _ = d.lan.Close(), d.core.Close()
	})
	d.wg.Wait()
	return nil
}

func (d *dualConn) LocalAddr() net.Addr              { return d.core.LocalAddr() }
func (d *dualConn) SetDeadline(time.Time) error      { return nil }
func (d *dualConn) SetReadDeadline(time.Time) error  { return nil }
func (d *dualConn) SetWriteDeadline(time.Time) error { return nil }

// lanServerCase is a pair of clients around a server that sits in a
// router's LAN as well as on the Internet.
type lanServerCase struct {
	name string
	// clients returns the initiator's and the responder's hosts.
	clients    func(n *nattest.Network, router *nattest.NAT) [2]*nattest.Host
	targets    coord.TargetPolicy
	lanPrefix  string
	wantKind   protocol.PathKind // "" expects a failure
	wantDetail string            // the failure's detail, when it matters
	wantHint   holepunch.Hint    // a hint the LAN client's diagnostics carry
}

func TestServerInClientLAN(t *testing.T) {
	inLAN := func(addrs ...string) func(*nattest.Network, *nattest.NAT) [2]*nattest.Host {
		return func(_ *nattest.Network, r *nattest.NAT) [2]*nattest.Host {
			if len(addrs) == 0 {
				return [2]*nattest.Host{r.Host(), r.Host()}
			}
			return [2]*nattest.Host{r.Host(netip.MustParseAddr(addrs[0])), r.Host(netip.MustParseAddr(addrs[1]))}
		}
	}
	lanAndOutside := func(_ *nattest.Network, r *nattest.NAT) [2]*nattest.Host {
		n := r.Host() // the LAN client first: it is the initiator
		return [2]*nattest.Host{n, nil}
	}
	for _, c := range []lanServerCase{
		{name: "both clients in the server's LAN", clients: inLAN(), wantKind: protocol.PathLAN, wantHint: holepunch.HintServerSeesLAN},
		{name: "LAN client and an outside peer", clients: lanAndOutside, wantKind: protocol.PathPublic, wantHint: holepunch.HintServerSeesLAN},
		{name: "LAN client and an outside peer, verified targets only", clients: lanAndOutside, targets: coord.TargetsVerifiedOnly,
			wantHint: holepunch.HintServerSeesLAN},
		{name: "LAN clients on two subnets, verified targets only", clients: inLAN("192.168.1.10", "192.168.2.10"),
			targets: coord.TargetsVerifiedOnly, lanPrefix: "192.168.0.0/16", wantDetail: plan.DetailNoTarget},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			runLANServerCase(t, c)
		})
	}
}

func runLANServerCase(t *testing.T, c lanServerCase) {
	n := nattest.NewNetwork(nattest.WithSeed(3))
	defer func() { _ = n.Close() }()
	prefix := netip.MustParsePrefix(cmpOr(c.lanPrefix, "192.168.1.0/24"))
	rcfg := nattest.PortRestricted()
	rcfg.LANPrefix = prefix
	router := n.NAT(rcfg)
	core, lanLeg := n.PublicHost(lanServerAddr), router.Host(lanServerAddr)
	listen := func(network string, laddr netip.AddrPort) (net.PacketConn, error) {
		cc, err := core.Listen(network, laddr)
		if err != nil {
			return nil, err
		}
		lc, err := lanLeg.Listen(network, netip.AddrPortFrom(laddr.Addr(), cc.LocalAddr().(*net.UDPAddr).AddrPort().Port()))
		if err != nil {
			_ = cc.Close()
			return nil, err
		}
		return newDualConn(lc, cc, prefix), nil
	}

	stunHost := n.PublicHost(netip.IPv4Unspecified())
	stunAddr := netip.AddrPortFrom(stunHost.Addrs()[0], 3478)
	stunConn, err := stunHost.Listen("udp4", stunAddr)
	if err != nil {
		t.Fatal(err)
	}
	var helpers sync.WaitGroup
	defer helpers.Wait()
	defer func() { _ = stunConn.Close() }()
	helpers.Go(func() { _ = stun.Serve(stunConn) })

	reg := natprobe.NewRegistry(natprobe.RegistryConfig{})
	probe, err := natprobe.NewServer(natprobe.ServerConfig{Registry: reg, Groups: []natprobe.ObserverGroup{{Bind: lanServerAddr}},
		Listen: listen, SourceRate: natprobe.Rate{PerSec: -1}})
	if err != nil {
		t.Fatal(err)
	}
	if err := probe.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = probe.Close() }()
	spec := probe.ProbeSpec()
	spec.STUN = []netip.AddrPort{stunAddr}
	res := make(chan coord.Result, 1)
	co, err := coord.New(coord.Config{
		Registry: reg, DefaultProbe: spec, Targets: c.targets,
		Timeouts: protocol.Timeouts{HandshakeTimeoutMs: 4000, MaxRounds: 2},
		OnResult: func(r coord.Result) { res <- r },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = co.Close() }()

	hosts := c.clients(n, router)
	if hosts[1] == nil {
		hosts[1] = n.NAT(nattest.PortRestricted()).Host()
	}
	sess, err := co.NewSession(coord.SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var (
		wg   sync.WaitGroup
		ends [2]net.Conn
		out  [2]*holepunch.Session
		errs [2]error
	)
	defer func() {
		for _, c := range ends {
			if c != nil {
				_ = c.Close()
			}
		}
	}()
	for i, role := range []protocol.Role{protocol.RoleInitiator, protocol.RoleResponder} {
		ce, se := n.Pipe(nattest.PipeConfig{A: hosts[i], B: core})
		ends[i] = ce
		if err := sess.Attach(role, se, coord.AttachOptions{Security: protocol.ControlSecurityInsecureForTesting}); err != nil {
			t.Fatal(err)
		}
		wg.Go(func() {
			out[i], errs[i] = holepunch.Punch(context.Background(), ce, holepunch.Options{
				ControlSecurity: protocol.ControlSecurityInsecureForTesting, Network: hosts[i],
			})
		})
	}
	wg.Wait()
	r := <-res
	if !slices.Contains(r.Warn, protocol.WarnLANObserved) {
		t.Errorf("coordinator warnings %v, want %s", r.Warn, protocol.WarnLANObserved)
	}

	var diag holepunch.Diagnostics
	if c.wantKind != "" {
		for i := range 2 {
			if errs[i] != nil {
				t.Fatalf("client %d: %v (coordinator: %s %s %s)", i, errs[i], r.Outcome, r.Reason, r.Detail)
			}
			if kind := out[i].Result().Path.Kind; kind != c.wantKind {
				t.Fatalf("client %d: %s path, want %s", i, kind, c.wantKind)
			}
		}
		diag = out[0].Diagnostics()
	} else {
		var herr *holepunch.Error
		if !errors.As(errs[0], &herr) || errs[1] == nil {
			t.Fatalf("sessions %v / %v, want both to fail", errs[0], errs[1])
		}
		if c.wantDetail != "" && (r.Detail != c.wantDetail || herr.Detail != c.wantDetail) {
			t.Fatalf("detail %q (client %q), want %q", r.Detail, herr.Detail, c.wantDetail)
		}
		if herr.Diagnostics != nil {
			diag = *herr.Diagnostics
		}
	}
	if c.wantHint == "" {
		return // the session ended before the summary: no traits to look at
	}
	if len(diag.Self) == 0 || !diag.Self[0].LANObserved || diag.Self[0].Mapping != protocol.MapUnknown {
		t.Fatalf("LAN client's traits %+v, want LAN-observed with an unknown mapping", diag.Self)
	}
	if !slices.ContainsFunc(diag.Families, func(f holepunch.FamilyDiagnostics) bool {
		return slices.Contains(f.Hints, c.wantHint)
	}) {
		t.Errorf("hints %+v, want %s", diag.Families, c.wantHint)
	}
}

func cmpOr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
