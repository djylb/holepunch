package natprobe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/protocol"
)

// stunLookupTimeout bounds the name lookup of one STUN server in ResolveSTUN.
const stunLookupTimeout = 3 * time.Second

// maxSTUNPerFamily is what a client asks of one family's STUN servers.
const maxSTUNPerFamily = protocol.MaxProbeSTUN / 2

// LookupFunc resolves host to its addresses, as net.Resolver.LookupNetIP
// does for network "ip".
type LookupFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

// ResolveSTUN turns STUN servers given as host:port or ip:port into the
// literal addresses ProbeSpec.STUN carries: the first IPv4 and the first IPv6
// address of each server, in the order of servers, at most 8 of each family
// (protocol.MaxProbeSTUN in all) — the 8 a client of that family asks. Names
// are looked up in parallel, each within 3 s and ctx, with lookup (nil: the
// system resolver), which runs inside a recover boundary. A server that
// cannot be parsed or resolved is left out, and its error is joined into
// err, so that a partial result comes with the reason for what is missing.
//
// Resolve again from time to time (hours) in a long-running server: the
// addresses behind a name change.
func ResolveSTUN(ctx context.Context, lookup LookupFunc, servers []string) ([]netip.AddrPort, error) {
	if lookup == nil {
		lookup = systemLookup
	}
	type resolved struct {
		i      int
		v4, v6 netip.AddrPort
		err    error
	}
	res := make([]resolved, len(servers))
	// Lookups report on a channel with room for all of them: one that
	// outlives the join below writes nothing the caller reads.
	done := make(chan resolved, len(servers))
	g := life.New(ctx)
	spawned := 0
	for i, server := range servers {
		host, portText, err := net.SplitHostPort(server)
		var port uint64
		if err == nil {
			port, err = strconv.ParseUint(portText, 10, 16)
		}
		if err == nil && port == 0 {
			err = errors.New("port 0")
		}
		if err != nil {
			res[i].err = fmt.Errorf("natprobe: STUN server %q: %v", server, err)
			continue
		}
		if ip, perr := netip.ParseAddr(host); perr == nil {
			res[i].v4, res[i].v6 = stunPick([]netip.Addr{ip}, uint16(port))
			if !res[i].v4.IsValid() && !res[i].v6.IsValid() {
				res[i].err = fmt.Errorf("natprobe: STUN server %q: not a global unicast address", server)
			}
			continue
		}
		res[i].err = fmt.Errorf("natprobe: STUN server %q: lookup did not finish", server)
		spawned++
		g.Go("natprobe.resolve_stun", func(ctx context.Context) {
			lctx, cancel := context.WithTimeout(ctx, stunLookupTimeout)
			defer cancel()
			var addrs []netip.Addr
			var lerr error
			if perr := life.Safe("natprobe.resolve_stun", func() { addrs, lerr = lookup(lctx, "ip", host) }); perr != nil {
				lerr = perr
			}
			r := resolved{i: i}
			if lerr == nil {
				r.v4, r.v6 = stunPick(addrs, uint16(port))
				if !r.v4.IsValid() && !r.v6.IsValid() {
					lerr = errors.New("no usable address")
				}
			}
			if lerr != nil {
				r.err = fmt.Errorf("natprobe: STUN server %q: %w", server, lerr)
			}
			done <- r
		})
	}
	// Every lookup ends within stunLookupTimeout; the timer only stops the
	// wait for one that ignores its context. Close cancels what is left.
	backstop := time.NewTimer(stunLookupTimeout + stunLookupTimeout/4)
	defer backstop.Stop()
collect:
	for range spawned {
		select {
		case r := <-done:
			res[r.i] = r
		case <-backstop.C:
			break collect
		}
	}
	_ = g.Close(stunLookupTimeout / 4)
	for len(done) > 0 {
		r := <-done
		res[r.i] = r
	}
	var v4, v6 []netip.AddrPort
	var errs []error
	for _, r := range res {
		if r.err != nil {
			errs = append(errs, r.err)
		}
		if r.v4.IsValid() && len(v4) < maxSTUNPerFamily && !contains(v4, r.v4) {
			v4 = append(v4, r.v4)
		}
		if r.v6.IsValid() && len(v6) < maxSTUNPerFamily && !contains(v6, r.v6) {
			v6 = append(v6, r.v6)
		}
	}
	return append(v4, v6...), errors.Join(errs...)
}

// stunPick returns the first global IPv4 and IPv6 address of addrs at port
// (not private, shared or link-local).
func stunPick(addrs []netip.Addr, port uint16) (v4, v6 netip.AddrPort) {
	for _, a := range addrs {
		a = a.Unmap().WithZone("")
		if nat.ScopeOf(a) != nat.ScopeGlobal {
			continue
		}
		switch {
		case a.Is4() && !v4.IsValid():
			v4 = netip.AddrPortFrom(a, port)
		case a.Is6() && !v6.IsValid():
			v6 = netip.AddrPortFrom(a, port)
		}
	}
	return v4, v6
}

func contains(list []netip.AddrPort, a netip.AddrPort) bool {
	for _, x := range list {
		if x == a {
			return true
		}
	}
	return false
}
