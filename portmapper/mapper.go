package portmapper

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/djylb/holepunch/internal/clock"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/protocol"
)

const (
	purposePortmap = "portmap" // the Network.ListenPacket purpose of every request socket
	pcpServerPort  = 5351      // PCP and NAT-PMP
	ssdpPort       = 1900

	// releaseTimeout bounds release and Close.
	releaseTimeout = 2 * time.Second
	// joinReserve is the part of Close's bound kept for joining the group
	// after the releases; every goroutine has been cancelled by then.
	joinReserve = 200 * time.Millisecond
	// minJoin keeps the join bound positive: life.Group.Close replaces a
	// non-positive bound with its 2 s default.
	minJoin = 50 * time.Millisecond
	// compensateTimeout bounds the delete sent for a mapping whose create
	// request was never answered.
	compensateTimeout = 500 * time.Millisecond
)

// Fault injection points.
const (
	pointMap   = "portmap.map"   // before each mapping request
	pointRenew = "portmap.renew" // before each renewal
)

// Mapper creates port mappings on the local gateway and renews them until
// they are released or the Mapper is closed. It satisfies
// holepunch.PortMapper and is safe for concurrent use.
//
// Stability: beta.
type Mapper struct {
	cfg Config
	g   *life.Group // every goroutine of the Mapper; its context ends when Close starts
	clk clock.Clock // renewal schedule and gateway cache expiry
	hc  *http.Client
	gw  gatewayCache

	// cleanup bounds the deletes that run in the group after Map has moved
	// on. They outlive the group's context, which Close cancels first; Close
	// cancels cleanup when its releases are due, so that they cannot hold up
	// the join.
	cleanup     context.Context
	stopCleanup context.CancelFunc

	closeOnce sync.Once
	closeErr  error

	mu     sync.Mutex
	closed bool
	leases map[*lease]struct{}

	// Set by New; tests in this package replace them before the first Map.
	discover      func(ctx context.Context) (netip.Addr, error)
	pcpPort       uint16 // PCP and NAT-PMP port on the gateway
	ssdpPort      uint16 // unicast SSDP port on the gateway
	ssdpMulticast bool   // also search the SSDP multicast group
}

// New returns a Mapper. It starts no goroutine and opens no socket until Map
// is called; a missing Config.Network makes every Map fail.
func New(cfg Config) *Mapper {
	cfg = cfg.withDefaults()
	m := &Mapper{
		cfg:           cfg,
		g:             life.New(context.Background()),
		clk:           clock.System{},
		hc:            newHTTPClient(),
		leases:        make(map[*lease]struct{}),
		discover:      cfg.Gateway,
		pcpPort:       pcpServerPort,
		ssdpPort:      ssdpPort,
		ssdpMulticast: true,
	}
	m.cleanup, m.stopCleanup = context.WithCancel(context.Background())
	if m.discover == nil {
		m.discover = func(context.Context) (netip.Addr, error) { return systemGateway() }
	}
	return m
}

// Map asks the gateway to forward a UDP port to conn's local port and renews
// the mapping until release is called or the Mapper is closed. conn is only
// inspected (LocalAddr): it is neither wrapped nor read, written or closed.
//
// policy selects the methods (a nil Enable* field means enabled) and the
// lease to request (LeaseSeconds 0 means one hour; other values are clamped
// to [60 s, 24 h]). Only IPv4 is supported, and a socket should be mapped at
// most once at a time. Map returns within Config.DiscoverTimeout plus twice
// Config.AttemptTimeout, or earlier when ctx ends; when Close runs meanwhile,
// it may take up to 2 s more to delete what it had created.
//
// release stops the renewal goroutine and then deletes the mapping. It is
// idempotent and safe for concurrent use, returns within 2 s, never closes
// conn, and every call returns the result of the first. The caller should
// call it before closing conn.
//
// Map never panics: a panic inside it is returned as an error that is or
// wraps a *life.PanicError. After Close, Map returns an error wrapping
// net.ErrClosed.
func (m *Mapper) Map(ctx context.Context, conn net.PacketConn, policy protocol.PortMappingPolicy) (info protocol.PortMappingInfo, release func() error, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var l *lease
	if perr := life.Safe("portmapper.Map", func() { l, err = m.mapConn(ctx, conn, policy) }); perr != nil {
		return protocol.PortMappingInfo{}, nil, perr
	}
	if err != nil {
		return protocol.PortMappingInfo{}, nil, err
	}
	return l.info, l.release, nil
}

// Close deletes every mapping the Mapper still holds, makes the Maps in
// flight return net.ErrClosed (each deletes what it had created) and joins
// the Mapper's goroutines. It is idempotent and safe for concurrent use,
// returns within about 2 s, and every call returns the first error.
func (m *Mapper) Close() error {
	m.closeOnce.Do(func() {
		if perr := life.Safe("portmapper.Close", func() { m.closeErr = m.shutdown() }); perr != nil {
			m.closeErr = perr
		}
	})
	return m.closeErr
}

func (m *Mapper) shutdown() error {
	deadline := time.Now().Add(releaseTimeout)
	cleanupBy := deadline.Add(-joinReserve)
	m.mu.Lock()
	m.closed = true
	leases := make([]*lease, 0, len(m.leases))
	for l := range m.leases {
		leases = append(leases, l)
	}
	m.mu.Unlock()
	// Cancelling the group first aborts the Maps in flight, their attempts,
	// the gateway lookup and every renewal, while the group still accepts the
	// release goroutines below.
	m.g.Fail(errMapperClosed)
	// The background deletes of mappings that those Maps created but do not
	// hand out get as long as the releases; then they are cancelled, so that
	// the join that follows stays within the bound.
	stopTimer := time.AfterFunc(time.Until(cleanupBy), m.stopCleanup)
	defer stopTimer.Stop()

	results := make(chan error, len(leases))
	for _, l := range leases {
		m.background("portmap.release", func(context.Context) {
			var err error
			defer func() { results <- err }()
			err = l.releaseBy(cleanupBy)
		})
	}
	var first error
	for range leases {
		if err := <-results; err != nil && first == nil {
			first = err
		}
	}
	if err := m.g.Close(max(time.Until(deadline), minJoin)); err != nil && first == nil {
		first = err
	}
	m.stopCleanup()
	if n := m.g.Stats().Leaked; n > 0 && first == nil {
		first = fmt.Errorf("portmapper: close: %d goroutines still running", n)
	}
	return first
}

// background runs fn in a goroutine of the group, behind its own recover
// boundary so that a panic fails fn and not the Mapper, and passes it the
// cleanup context. Once Close is joining the group, fn runs in the calling
// goroutine with a background context instead, so cleanup work is never
// skipped; the callers (Map and Close) are not goroutines of the group, so
// this cannot delay the join.
func (m *Mapper) background(name string, fn func(ctx context.Context)) {
	if !m.g.Go(name, func(context.Context) { _ = life.Safe(name, func() { fn(m.cleanup) }) }) {
		_ = life.Safe(name, func() { fn(context.Background()) })
	}
}

// discard deletes, best effort and in the background, a mapping that Map
// created or may have created but does not hand out.
func (m *Mapper) discard(r remover, timeout time.Duration) {
	m.background("portmap.discard", func(ctx context.Context) { removeWithin(ctx, r, timeout) })
}

// register hands a created mapping to a new lease, or deletes it when Close
// has started meanwhile.
func (m *Mapper) register(live liveMapping, info protocol.PortMappingInfo) (*lease, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), releaseTimeout)
		defer cancel()
		_ = live.remove(ctx)
		return nil, errMapperClosed
	}
	l := newLease(m, live, info)
	m.leases[l] = struct{}{}
	m.mu.Unlock()
	l.start()
	return l, nil
}

func (m *Mapper) forget(l *lease) {
	m.mu.Lock()
	delete(m.leases, l)
	m.mu.Unlock()
}

func (m *Mapper) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

// ctxErr maps the end of a Map's context to the error Map returns.
func (m *Mapper) ctxErr(ctx context.Context) error {
	if m.g.Context().Err() != nil {
		return errMapperClosed
	}
	return fmt.Errorf("portmapper: %w", context.Cause(ctx))
}
