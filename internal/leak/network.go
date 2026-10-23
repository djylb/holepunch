package leak

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/djylb/holepunch/internal/life"
)

// Network is the method set of holepunch.Network.
type Network interface {
	ListenPacket(ctx context.Context, network string, laddr netip.AddrPort, purpose string) (net.PacketConn, error)
	InterfaceAddrs() ([]net.Interface, [][]netip.Prefix, error)
	OutboundAddr(ctx context.Context, network string) (netip.Addr, error)
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// HopLimiter is the optional TTL/HopLimit capability of a packet conn, with
// the signature of holepunch.HopLimiter.
type HopLimiter interface {
	SetHopLimit(hops int) error
}

// Count is the socket count of one purpose, or of all.
type Count struct {
	Opened int // ListenPacket returned a conn
	Closed int // of those, closed (the first Close counts)
	Failed int // ListenPacket returned an error or a nil or typed-nil conn
}

// Open returns the number of sockets still open.
func (c Count) Open() int { return c.Opened - c.Closed }

// Stats is a snapshot of a TrackingNetwork's counts.
type Stats struct {
	Total     Count
	ByPurpose map[string]Count
}

// OpenConn describes a tracked conn that has not been closed.
type OpenConn struct {
	ID      uint64 // order of opening, from 1
	Purpose string
	Network string
	Local   string // local address at open time
}

// String formats the conn for leak reports: "#id purpose network local".
func (o OpenConn) String() string {
	return fmt.Sprintf("#%d %s %s %s", o.ID, o.Purpose, o.Network, o.Local)
}

// errNoInner is returned by a TrackingNetwork created without a Network.
var errNoInner = errors.New("leak: TrackingNetwork has no inner Network")

// TrackingNetwork is a Network that counts the sockets of an inner Network.
// Create it with NewTrackingNetwork.
type TrackingNetwork struct {
	inner Network

	mu     sync.Mutex
	seq    uint64
	counts map[string]*Count
	open   map[*trackedConn]OpenConn
}

// trackedConn is the record of one tracked conn: its identity in open.
type trackedConn struct{ purpose string }

var _ Network = (*TrackingNetwork)(nil)

// NewTrackingNetwork returns a TrackingNetwork that delegates to inner.
func NewTrackingNetwork(inner Network) *TrackingNetwork {
	return &TrackingNetwork{
		inner:  inner,
		counts: make(map[string]*Count),
		open:   make(map[*trackedConn]OpenConn),
	}
}

// ListenPacket opens a socket through the inner Network and tracks it under
// purpose. A failed call, or a nil or typed-nil conn, is counted as Failed
// and returned unchanged: the conn is not wrapped, so that the library's own
// typed-nil check still sees it.
func (t *TrackingNetwork) ListenPacket(ctx context.Context, network string, laddr netip.AddrPort, purpose string) (net.PacketConn, error) {
	if t.inner == nil {
		return nil, errNoInner
	}
	pc, err := t.inner.ListenPacket(ctx, network, laddr, purpose)
	if err != nil || life.IsNil(pc) {
		t.failed(purpose)
		return pc, err
	}
	local := "?"
	if a := pc.LocalAddr(); !life.IsNil(a) {
		local = a.String()
	}
	tc := &trackedConn{purpose: purpose}
	t.opened(tc, network, local)
	return Wrap(pc, Hooks{Close: func() { t.closed(tc) }}), nil
}

// InterfaceAddrs delegates to the inner Network.
func (t *TrackingNetwork) InterfaceAddrs() ([]net.Interface, [][]netip.Prefix, error) {
	if t.inner == nil {
		return nil, nil, errNoInner
	}
	return t.inner.InterfaceAddrs()
}

// OutboundAddr delegates to the inner Network.
func (t *TrackingNetwork) OutboundAddr(ctx context.Context, network string) (netip.Addr, error) {
	if t.inner == nil {
		return netip.Addr{}, errNoInner
	}
	return t.inner.OutboundAddr(ctx, network)
}

// LookupNetIP delegates to the inner Network.
func (t *TrackingNetwork) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if t.inner == nil {
		return nil, errNoInner
	}
	return t.inner.LookupNetIP(ctx, network, host)
}

// Stats returns the counts in total and by purpose.
func (t *TrackingNetwork) Stats() Stats {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := Stats{ByPurpose: make(map[string]Count, len(t.counts))}
	for p, c := range t.counts {
		s.ByPurpose[p] = *c
		s.Total.Opened += c.Opened
		s.Total.Closed += c.Closed
		s.Total.Failed += c.Failed
	}
	return s
}

// Open returns the number of tracked sockets that have not been closed.
func (t *TrackingNetwork) Open() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.open)
}

// OpenConns lists the tracked sockets that have not been closed, oldest
// first.
func (t *TrackingNetwork) OpenConns() []OpenConn {
	t.mu.Lock()
	out := make([]OpenConn, 0, len(t.open))
	for _, o := range t.open {
		out = append(out, o)
	}
	t.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// CheckOpen returns nil if exactly want tracked sockets are open (1 after a
// successful session, 0 after a failed one), and otherwise an error listing
// the open sockets.
func (t *TrackingNetwork) CheckOpen(want int) error {
	open := t.OpenConns()
	if len(open) == want {
		return nil
	}
	list := make([]string, len(open))
	for i, o := range open {
		list[i] = o.String()
	}
	return fmt.Errorf("leak: %d sockets open, want %d: [%s]", len(open), want, strings.Join(list, "; "))
}

// CheckClosed returns nil if every tracked socket has been closed.
func (t *TrackingNetwork) CheckClosed() error { return t.CheckOpen(0) }

func (t *TrackingNetwork) opened(c *trackedConn, network, local string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.seq++
	t.count(c.purpose).Opened++
	t.open[c] = OpenConn{ID: t.seq, Purpose: c.purpose, Network: network, Local: local}
}

func (t *TrackingNetwork) failed(purpose string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.count(purpose).Failed++
}

// closed records the first Close of c; later calls change nothing.
func (t *TrackingNetwork) closed(c *trackedConn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.open[c]; !ok {
		return
	}
	delete(t.open, c)
	t.count(c.purpose).Closed++
}

func (t *TrackingNetwork) count(purpose string) *Count {
	c := t.counts[purpose]
	if c == nil {
		c = &Count{}
		t.counts[purpose] = c
	}
	return c
}
