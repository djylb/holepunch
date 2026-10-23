package portmapper

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/netaddr"
	"github.com/djylb/holepunch/protocol"
)

// Lease bounds applied to PortMappingPolicy.LeaseSeconds.
const (
	minLease = time.Minute
	maxLease = 24 * time.Hour
)

// preference is the order in which methods provide a mapping.
var preference = [...]protocol.PortMapMethod{protocol.PortMapPCP, protocol.PortMapNATPMP, protocol.PortMapUPnP}

// attemptResult is what the parallel phase of one method produced. On
// success it holds either the mapping (PCP creates it in that phase) or the
// creator of the mapping (NAT-PMP and UPnP, after a probe without effect on
// the gateway). On failure it may hold a mapping that the gateway created
// anyway.
type attemptResult struct {
	live   liveMapping
	info   protocol.PortMappingInfo
	create creator
	orphan remover
	err    error
}

// creator requests a mapping of the local port after a successful probe. Like
// pcpCreate, it returns as orphan a mapping the gateway may hold although the
// request failed.
type creator func(ctx context.Context, port uint16, lease time.Duration) (live liveMapping, info protocol.PortMappingInfo, orphan remover, err error)

// attempt is the parallel phase of one method. Its goroutine hands the result
// to Map, or disposes of it when Map has stopped waiting.
type attempt struct {
	method protocol.PortMapMethod
	ready  chan struct{} // closed once res is set

	mu        sync.Mutex
	res       attemptResult
	delivered bool
	abandoned bool
}

func newAttempt(method protocol.PortMapMethod) *attempt {
	return &attempt{method: method, ready: make(chan struct{})}
}

// mapConn is Map inside its recover boundary. It finds the gateway, runs the
// parallel phase of every enabled method and lets the most preferred method
// that succeeded provide the mapping.
func (m *Mapper) mapConn(ctx context.Context, conn net.PacketConn, policy protocol.PortMappingPolicy) (*lease, error) {
	if m.isClosed() {
		return nil, errMapperClosed
	}
	if life.IsNil(m.cfg.Network) {
		return nil, errNoNetwork
	}
	bind, port, err := localAddr(conn)
	if err != nil {
		return nil, err
	}
	methods := enabledMethods(policy)
	if len(methods) == 0 {
		return nil, fmt.Errorf("%w: every method is disabled by the policy", ErrUnsupported)
	}
	leaseFor := leaseDuration(policy)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(m.g.Context(), cancel)
	defer stop()

	local, gw, gwErr, err := m.locate(ctx, bind)
	if err != nil {
		return nil, err
	}

	// The parallel phase and the mapping requests that follow it share a
	// bound of twice AttemptTimeout; each step also has its own.
	pctx, pcancel := context.WithTimeout(ctx, 2*m.cfg.AttemptTimeout)
	defer pcancel()
	attempts := make([]*attempt, 0, len(methods))
	consumed := make([]bool, len(methods))
	defer func() {
		cancel() // stop the attempts still running before abandoning them
		for i, a := range attempts {
			if !consumed[i] {
				m.abandon(a)
			}
		}
	}()
	for _, method := range methods {
		a := newAttempt(method)
		attempts = append(attempts, a)
		if gwErr != nil && method != protocol.PortMapUPnP {
			m.deliver(a, attemptResult{err: fmt.Errorf("%s: %w", method, gwErr)})
			continue
		}
		if !m.g.Go("portmap.attempt", func(context.Context) { m.runAttempt(pctx, a, gw, local, port, leaseFor) }) {
			m.deliver(a, attemptResult{err: errMapperClosed})
			return nil, errMapperClosed
		}
	}

	var errs multiError
	for i, a := range attempts {
		select {
		case <-a.ready:
			consumed[i] = true
		case <-ctx.Done():
			return nil, m.ctxErr(ctx)
		}
		live, info, err := m.create(pctx, a.method, a.res, port, leaseFor)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		return m.register(live, info)
	}

	if ctx.Err() != nil {
		return nil, m.ctxErr(ctx)
	}
	if gwErr == nil {
		m.invalidateGateway(gw) // nothing answered: look the gateway up again next time
	}
	upnpOff := !policy.Enabled(protocol.PortMapUPnP)
	if gwErr != nil && (upnpOff || errors.Is(errs, errNoIGD)) {
		return nil, fmt.Errorf("%w: %w", ErrNoGateway, errs)
	}
	return nil, fmt.Errorf("%w: %w", ErrUnsupported, errs)
}

// locate finds, within DiscoverTimeout, the local address the gateway sees
// and the gateway. err ends the Map; gwErr only rules out PCP and NAT-PMP,
// since UPnP can still find a gateway by multicast.
func (m *Mapper) locate(ctx context.Context, bind netip.Addr) (local, gw netip.Addr, gwErr, err error) {
	dctx, cancel := context.WithTimeoutCause(ctx, m.cfg.DiscoverTimeout, errDiscoverTimeout)
	defer cancel()
	// The address the gateway sees: the socket's own, or the one that routes
	// out when it is bound to a wildcard address. Request sockets are bound to
	// it so that PCP's client address matches the packets' source.
	local = bind
	if !local.IsValid() {
		if local, err = m.outbound(dctx); err != nil {
			if ctx.Err() != nil {
				err = m.ctxErr(ctx)
			}
			return netip.Addr{}, netip.Addr{}, nil, err
		}
	}
	gw, gwErr = m.lookupGateway(dctx)
	switch {
	case ctx.Err() != nil:
		err = m.ctxErr(ctx)
	case errors.Is(gwErr, errMapperClosed):
		err = errMapperClosed
	}
	return local, gw, gwErr, err
}

// runAttempt is the parallel phase of one method. It runs in a goroutine of
// the group and always delivers exactly one result, also when the attempt
// panics.
func (m *Mapper) runAttempt(ctx context.Context, a *attempt, gw, local netip.Addr, port uint16, lease time.Duration) {
	var r attemptResult
	if perr := life.Safe("portmap.attempt", func() {
		actx, cancel := context.WithTimeout(ctx, m.cfg.AttemptTimeout)
		defer cancel()
		server := netip.AddrPortFrom(gw, m.pcpPort)
		switch a.method {
		case protocol.PortMapPCP:
			r.live, r.info, r.orphan, r.err = pcpCreate(actx, m.openRequest, server, local, port, lease)
		case protocol.PortMapNATPMP:
			var p *natpmpProbe
			if p, r.err = natpmpDiscover(actx, m.openRequest, server, local); r.err == nil {
				r.create = p.create
			}
		case protocol.PortMapUPnP:
			var p *upnpProbe
			if p, r.err = upnpDiscover(actx, m.openRequest, m.hc, local, gw, m.ssdpPort, m.ssdpMulticast); r.err == nil {
				r.create = p.create
			}
		}
	}); perr != nil {
		r = attemptResult{err: fmt.Errorf("%s: %w", a.method, perr)}
	}
	m.deliver(a, r)
}

// deliver hands r to the Map waiting for a, or, when that Map has stopped
// waiting, deletes what r created. The delete then runs in the attempt's
// goroutine, bounded by the cleanup context.
func (m *Mapper) deliver(a *attempt, r attemptResult) {
	a.mu.Lock()
	if a.abandoned {
		a.mu.Unlock()
		m.dispose(m.cleanup, r)
		return
	}
	a.res, a.delivered = r, true
	a.mu.Unlock()
	close(a.ready)
}

// abandon tells a's goroutine that Map no longer waits for it. A result
// that was already delivered is disposed of here.
func (m *Mapper) abandon(a *attempt) {
	a.mu.Lock()
	r, delivered := a.res, a.delivered
	a.abandoned = true
	a.mu.Unlock()
	if delivered && (r.live != nil || r.orphan != nil) {
		m.background("portmap.abandon", func(ctx context.Context) { m.dispose(ctx, r) })
	}
}

// dispose deletes the mapping r created, or the one it may have created.
func (m *Mapper) dispose(parent context.Context, r attemptResult) {
	if r.live != nil {
		removeWithin(parent, r.live, releaseTimeout)
	}
	if r.orphan != nil {
		removeWithin(parent, r.orphan, compensateTimeout)
	}
}

// removeWithin deletes a mapping, best effort, within timeout.
func removeWithin(parent context.Context, r remover, timeout time.Duration) {
	_ = life.Safe("portmap.remove", func() {
		ctx, cancel := context.WithTimeout(parent, timeout)
		defer cancel()
		_ = r.remove(ctx)
	})
}

// create turns the result of a method's parallel phase into a mapping: PCP's
// was created in that phase, NAT-PMP and UPnP create theirs now. A panic
// fails this method only, so the next one is still tried.
func (m *Mapper) create(ctx context.Context, method protocol.PortMapMethod, r attemptResult, port uint16, lease time.Duration) (live liveMapping, info protocol.PortMappingInfo, err error) {
	if r.orphan != nil {
		m.discard(r.orphan, compensateTimeout)
	}
	if r.err != nil || r.create == nil {
		return r.live, r.info, r.err
	}
	cctx, cancel := context.WithTimeout(ctx, m.cfg.AttemptTimeout)
	defer cancel()
	if perr := life.Safe("portmap.create", func() {
		var orphan remover
		if live, info, orphan, err = r.create(cctx, port, lease); orphan != nil {
			m.discard(orphan, compensateTimeout)
		}
	}); perr != nil {
		return nil, protocol.PortMappingInfo{}, fmt.Errorf("%s: %w", method, perr)
	}
	return live, info, err
}

// enabledMethods lists the methods policy allows, in preference order.
func enabledMethods(p protocol.PortMappingPolicy) []protocol.PortMapMethod {
	out := make([]protocol.PortMapMethod, 0, len(preference))
	for _, method := range preference {
		if p.Enabled(method) {
			out = append(out, method)
		}
	}
	return out
}

// leaseDuration is the lease to request: the policy's (one hour when unset),
// clamped to what gateways commonly accept.
func leaseDuration(p protocol.PortMappingPolicy) time.Duration {
	return min(max(p.Lease(), minLease), maxLease)
}

// localAddr returns the IPv4 address conn is bound to (invalid for a wildcard
// bind) and its port. LocalAddr is the only method of conn that is called.
func localAddr(conn net.PacketConn) (netip.Addr, uint16, error) {
	if life.IsNil(conn) {
		return netip.Addr{}, 0, errNilConn
	}
	var la net.Addr
	if perr := life.Safe("conn.LocalAddr", func() { la = conn.LocalAddr() }); perr != nil {
		return netip.Addr{}, 0, perr
	}
	if life.IsNil(la) {
		return netip.Addr{}, 0, errors.New("portmapper: conn has no local address")
	}
	ap := netaddr.AddrPortOf(la)
	if !ap.IsValid() {
		return netip.Addr{}, 0, fmt.Errorf("portmapper: conn local address %q is not an ip:port", la)
	}
	if ap.Port() == 0 {
		return netip.Addr{}, 0, fmt.Errorf("portmapper: conn local address %s has no port", la)
	}
	ip := ap.Addr().Unmap()
	switch {
	case !ip.IsValid() || ip.IsUnspecified():
		return netip.Addr{}, ap.Port(), nil
	case ip.Is4():
		return ip, ap.Port(), nil
	default:
		return netip.Addr{}, 0, fmt.Errorf("%w: conn is bound to IPv6 address %s", ErrUnsupported, ip)
	}
}
