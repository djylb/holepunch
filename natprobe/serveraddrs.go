package natprobe

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/clock"
	"github.com/djylb/holepunch/hostaddr"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/netaddr"
)

// ServerAddrsConfig configures a ServerAddrs. Every field is optional.
type ServerAddrsConfig struct {
	// Public lists fixed addresses the clients reach the server at that its
	// sockets do not show: the outside address of a 1:1 NAT, a second
	// address routed to the host.
	Public []netip.Addr
	// Names are DNS names that point at the server (a DDNS name), looked
	// up with Lookup; every address of a name counts.
	Names []string
	// HostPublic adds the global addresses of the host's own interfaces
	// (hostaddr.Public, on an interface that is up): a server on the
	// Internet without NAT, whose address may change.
	HostPublic bool
	// Lookup resolves Names; nil uses the system resolver.
	Lookup LookupFunc
	// Interfaces lists the host's addresses for HostPublic; nil uses
	// hostaddr.List.
	//holepunch:callback
	Interfaces func() ([]hostaddr.Addr, error)
	// Refresh is how often Names and the interfaces are read again; 0 means
	// 5 min.
	Refresh time.Duration
	// Clock schedules the refreshes; nil uses the system clock.
	Clock clock.Clock
	// Logger, optional, receives the failed lookups and interface reads at
	// Warn.
	Logger *slog.Logger
}

// ServerAddrs collects the addresses a client may reach this server at, for
// Server.ProbeSpecAt: the local address of the client's own control
// connection (For), the configured Public addresses, the addresses of Names
// and, with HostPublic, the host's global interface addresses — in that
// order, which is the order of usefulness ProbeSpecAt keeps when its slots
// run out, without duplicates. Names and interfaces are read by Refresh and
// Run; a name or an interface list that cannot be read keeps its previous
// addresses. The methods are safe for concurrent use; a nil *ServerAddrs
// holds no address.
type ServerAddrs struct {
	cfg ServerAddrsConfig
	r   refresher
	mu  sync.Mutex // serializes Refresh, which builds on the current snapshot
	cur atomic.Pointer[addrSnapshot]
}

// addrSnapshot is the result of one refresh: each name's addresses, the
// host's, and every address in order.
type addrSnapshot struct {
	names [][]netip.Addr
	host  []netip.Addr
	all   []netip.Addr
}

// NewServerAddrs returns the addresses of cfg. The Public addresses are
// there at once; Names and the interfaces after the first Refresh, or once
// Run has started.
func NewServerAddrs(cfg ServerAddrsConfig) *ServerAddrs {
	cfg.Public = slices.Clone(cfg.Public)
	cfg.Names = slices.Clone(cfg.Names)
	a := &ServerAddrs{cfg: cfg, r: newRefresher(cfg.Clock, cfg.Logger, cfg.Refresh, defaultAddrsRefresh, 0)}
	a.store(&addrSnapshot{names: make([][]netip.Addr, len(cfg.Names))})
	return a
}

// Addrs returns every address but a control connection's, in order (a
// copy).
func (a *ServerAddrs) Addrs() []netip.Addr {
	if a == nil {
		return nil
	}
	return slices.Clone(a.cur.Load().all)
}

// For returns the addresses for a session of the client on control: the
// local address of control first — the address that client connected to,
// unless it is a wildcard — then Addrs. control may be nil; its LocalAddr
// is called inside a recover boundary.
func (a *ServerAddrs) For(control net.Conn) []netip.Addr {
	var out []netip.Addr
	if !life.IsNil(control) {
		var local netip.Addr
		_ = life.Safe("natprobe/control.LocalAddr", func() { local = netaddr.AddrPortOf(control.LocalAddr()).Addr() })
		out = appendAddr(out, local)
	}
	for _, x := range a.Addrs() {
		out = appendAddr(out, x)
	}
	return out
}

// Refresh looks Names up and reads the host's interfaces now, and returns
// what failed. A name that cannot be resolved, and an interface list that
// cannot be read, keep their previous addresses.
func (a *ServerAddrs) Refresh(ctx context.Context) error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	prev := a.cur.Load()
	next := &addrSnapshot{names: slices.Clone(prev.names), host: prev.host}
	var errs []error
	addrs, lerrs := lookupHosts(ctx, a.cfg.Lookup, a.cfg.Names)
	for i, name := range a.cfg.Names {
		switch {
		case lerrs[i] != nil:
			errs = append(errs, fmt.Errorf("natprobe: server name %q: %w", name, lerrs[i]))
		case len(addrs[i]) == 0:
			errs = append(errs, fmt.Errorf("natprobe: server name %q: no address", name))
		default:
			next.names[i] = addrs[i]
		}
	}
	if a.cfg.HostPublic {
		host, err := a.hostPublic()
		if err != nil {
			errs = append(errs, fmt.Errorf("natprobe: host interfaces: %w", err))
		} else {
			next.host = host
		}
	}
	a.store(next)
	a.r.done.Store(true)
	err := errors.Join(errs...)
	if err != nil {
		a.r.record(slog.LevelWarn, "natprobe: server addresses", "err", err)
	}
	return err
}

// Run reads Names and the interfaces at once, unless Refresh already did,
// and then every Refresh until ctx ends. With neither Names nor HostPublic
// there is nothing to read and it returns at once. It blocks: start it on a
// goroutine of the caller's.
func (a *ServerAddrs) Run(ctx context.Context) {
	if a == nil || (len(a.cfg.Names) == 0 && !a.cfg.HostPublic) {
		return
	}
	a.r.run(ctx, func(ctx context.Context) { _ = a.Refresh(ctx) }, func() bool { return true })
}

// hostPublic returns the global addresses of the interfaces that are up.
func (a *ServerAddrs) hostPublic() (out []netip.Addr, err error) {
	list := a.cfg.Interfaces
	if list == nil {
		list = hostaddr.List
	}
	var ifs []hostaddr.Addr
	if perr := life.Safe("natprobe/interfaces", func() { ifs, err = list() }); perr != nil {
		return nil, perr
	}
	if err != nil {
		return nil, err
	}
	for _, x := range ifs {
		if x.Up && x.Kind == hostaddr.Public {
			out = append(out, x.Addr())
		}
	}
	return out, nil
}

// store completes s with every address in order and publishes it.
func (a *ServerAddrs) store(s *addrSnapshot) {
	var all []netip.Addr
	for _, x := range a.cfg.Public {
		all = appendAddr(all, x)
	}
	for _, l := range s.names {
		for _, x := range l {
			all = appendAddr(all, x)
		}
	}
	for _, x := range s.host {
		all = appendAddr(all, x)
	}
	s.all = all
	a.cur.Store(s)
}

// appendAddr appends x, unmapped, unless it is not a unicast address that
// works without a zone (link-local) or already in list.
func appendAddr(list []netip.Addr, x netip.Addr) []netip.Addr {
	x = x.Unmap()
	if !x.IsValid() || x.IsUnspecified() || x.IsMulticast() || x.IsLinkLocalUnicast() || slices.Contains(list, x) {
		return list
	}
	return append(list, x)
}
