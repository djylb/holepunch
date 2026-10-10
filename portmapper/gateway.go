package portmapper

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/djylb/holepunch/internal/life"
)

// Cache lifetimes of the gateway lookup. A failure is cached briefly so that
// a host without a default route does not run the lookup for every Map; a
// Map that gets no answer from a cached gateway invalidates it, so a network
// change is picked up by the next Map.
const (
	gatewayTTL         = time.Minute
	gatewayNegativeTTL = 5 * time.Second
)

// gatewayCache is a Mapper's gateway lookup: one lookup at a time
// (single-flight) and its cached result. A caller typically creates one Mapper
// per process, so the cache is effectively process-wide without being global
// state.
type gatewayCache struct {
	mu      sync.Mutex
	valid   bool
	addr    netip.Addr
	err     error
	expires time.Time
	call    *gatewayCall // lookup in flight
}

type gatewayCall struct {
	done chan struct{} // closed when addr and err are set
	addr netip.Addr
	err  error
}

// lookupGateway returns the cached gateway, or waits for the shared lookup
// until ctx ends. The lookup runs in a goroutine of the group because the
// operating system lookup cannot be cancelled: a Map stops waiting for it
// instead, and Close joins it.
func (m *Mapper) lookupGateway(ctx context.Context) (netip.Addr, error) {
	c := &m.gw
	now := m.clk.Now()
	c.mu.Lock()
	if c.valid && now.Before(c.expires) {
		addr, err := c.addr, c.err
		c.mu.Unlock()
		return addr, err
	}
	call := c.call
	if call == nil {
		call = &gatewayCall{done: make(chan struct{})}
		if !m.g.Go("portmap.gateway", func(gctx context.Context) { m.runLookup(gctx, call) }) {
			c.mu.Unlock()
			return netip.Addr{}, errMapperClosed
		}
		c.call = call
	}
	c.mu.Unlock()

	select {
	case <-call.done:
		return call.addr, call.err
	case <-ctx.Done():
		return netip.Addr{}, fmt.Errorf("%w: %w", ErrNoGateway, context.Cause(ctx))
	}
}

func (m *Mapper) runLookup(ctx context.Context, call *gatewayCall) {
	var addr netip.Addr
	var err error
	if perr := life.Safe("portmap.gateway", func() { addr, err = m.discover(ctx) }); perr != nil {
		err = perr
	}
	addr = addr.Unmap()
	if err == nil && !addr.Is4() {
		err = fmt.Errorf("%w: %s", errNotIPv4Gateway, addr)
	}
	if err != nil {
		addr, err = netip.Addr{}, fmt.Errorf("%w: %w", ErrNoGateway, err)
	}
	ttl := gatewayTTL
	if err != nil {
		ttl = gatewayNegativeTTL
	}
	expires := m.clk.Now().Add(ttl)
	c := &m.gw
	c.mu.Lock()
	call.addr, call.err = addr, err
	c.call = nil
	c.valid, c.addr, c.err, c.expires = true, addr, err, expires
	c.mu.Unlock()
	close(call.done)
}

// invalidateGateway drops the cached entry if it still names addr.
func (m *Mapper) invalidateGateway(addr netip.Addr) {
	c := &m.gw
	c.mu.Lock()
	if c.valid && c.addr == addr {
		c.valid = false
	}
	c.mu.Unlock()
}
