package natprobe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/netaddr"
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
// The addresses behind a name change: a long-running server keeps the list
// fresh with a STUNList, which resolves again from time to time.
func ResolveSTUN(ctx context.Context, lookup LookupFunc, servers []string) ([]netip.AddrPort, error) {
	type resolved struct {
		v4, v6 netip.AddrPort
		err    error
	}
	res := make([]resolved, len(servers))
	ports := make([]uint16, len(servers))
	var names []string
	var named []int // names[k] is servers[named[k]]
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
		ports[i] = uint16(port)
		if ip, perr := netip.ParseAddr(host); perr == nil {
			res[i].v4, res[i].v6 = stunPick([]netip.Addr{ip}, ports[i])
			if !res[i].v4.IsValid() && !res[i].v6.IsValid() {
				res[i].err = fmt.Errorf("natprobe: STUN server %q: not a global unicast address", server)
			}
			continue
		}
		names = append(names, host)
		named = append(named, i)
	}
	addrs, errs := lookupHosts(ctx, lookup, names)
	for k, i := range named {
		r := &res[i]
		lerr := errs[k]
		if lerr == nil {
			r.v4, r.v6 = stunPick(addrs[k], ports[i])
			if !r.v4.IsValid() && !r.v6.IsValid() {
				lerr = errors.New("no usable address")
			}
		}
		if lerr != nil {
			r.err = fmt.Errorf("natprobe: STUN server %q: %w", servers[i], lerr)
		}
	}
	var v4, v6 []netip.AddrPort
	var all []error
	for _, r := range res {
		if r.err != nil {
			all = append(all, r.err)
		}
		if r.v4.IsValid() && len(v4) < maxSTUNPerFamily && !slices.Contains(v4, r.v4) {
			v4 = append(v4, r.v4)
		}
		if r.v6.IsValid() && len(v6) < maxSTUNPerFamily && !slices.Contains(v6, r.v6) {
			v6 = append(v6, r.v6)
		}
	}
	return append(v4, v6...), errors.Join(all...)
}

// errLookupUnfinished is the error of a lookup that did not report back
// before lookupHosts gave up on it.
var errLookupUnfinished = errors.New("lookup did not finish")

// lookupHosts looks hosts up in parallel with lookup (nil: the system
// resolver) for network "ip", each within 3 s and ctx; lookup runs inside a
// recover boundary. addrs[i] and errs[i] are hosts[i]'s. It returns within
// about 4 s even when a lookup ignores its context, which then counts as
// errLookupUnfinished.
func lookupHosts(ctx context.Context, lookup LookupFunc, hosts []string) (addrs [][]netip.Addr, errs []error) {
	if lookup == nil {
		lookup = systemLookup
	}
	addrs = make([][]netip.Addr, len(hosts))
	errs = make([]error, len(hosts))
	if len(hosts) == 0 {
		return addrs, errs
	}
	type result struct {
		i     int
		addrs []netip.Addr
		err   error
	}
	// Lookups report on a channel with room for all of them: one that
	// outlives the join below writes nothing the caller reads.
	done := make(chan result, len(hosts))
	g := life.New(ctx)
	for i, host := range hosts {
		errs[i] = errLookupUnfinished
		g.Go("natprobe.lookup", func(ctx context.Context) {
			lctx, cancel := context.WithTimeout(ctx, stunLookupTimeout)
			defer cancel()
			r := result{i: i}
			if perr := life.Safe("natprobe.lookup", func() { r.addrs, r.err = lookup(lctx, "ip", host) }); perr != nil {
				r.addrs, r.err = nil, perr
			}
			done <- r
		})
	}
	// Every lookup ends within stunLookupTimeout; the timer only stops the
	// wait for one that ignores its context. Close cancels what is left.
	backstop := time.NewTimer(stunLookupTimeout + stunLookupTimeout/4)
	defer backstop.Stop()
	store := func(r result) { addrs[r.i], errs[r.i] = r.addrs, r.err }
collect:
	for range hosts {
		select {
		case r := <-done:
			store(r)
		case <-backstop.C:
			break collect
		}
	}
	_ = g.Close(stunLookupTimeout / 4)
	for len(done) > 0 {
		store(<-done)
	}
	return addrs, errs
}

// stunPick returns the first global IPv4 and IPv6 address of addrs at port
// (not private, shared or link-local).
func stunPick(addrs []netip.Addr, port uint16) (v4, v6 netip.AddrPort) {
	for _, a := range addrs {
		a = a.Unmap().WithZone("")
		if !netaddr.Public(a) {
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
