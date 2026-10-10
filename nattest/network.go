package nattest

import (
	"hash/fnv"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/internal/clock"
)

// inboxPackets is the receive queue of a socket, in packets.
const inboxPackets = 1024

// Network is the simulated Internet core together with everything attached
// to it. Create it with [NewNetwork] and release it with [Network.Close]. All
// methods are safe for concurrent use.
type Network struct {
	seed     int64
	clock    clock.Clock
	system   bool      // clock is clock.System
	base     time.Time // network time 0
	coreHops int
	queue    int // receive queue of new sockets, in packets

	core     *realm
	coreLink *link
	sched    *scheduler
	log      *eventLog

	topo     sync.RWMutex // guards the fields below and the owners of every realm
	hosts    []*Host
	nats     []*NAT
	pipes    []*pipe
	dns      map[string][]netip.Addr
	natNames map[string]int
	nextPub4 int // index of the next automatic public IPv4 address
	nextSite int // number of public IPv6 /64 sites handed out

	closed    atomic.Bool // set under topo
	closeOnce sync.Once
	closeErr  error

	sent, delivered atomic.Uint64
	drops           dropCounters // drops in the core, on its link and at Close
}

// NewNetwork creates an empty network. Unless the clock is a *clock.Fake it
// starts the scheduler goroutine, so the caller must Close the network.
func NewNetwork(opts ...Option) *Network {
	o := options{seed: defaultSeed, coreHops: defaultCoreHops, eventLog: defaultEventLog, clock: clock.System{}}
	for _, f := range opts {
		if f != nil {
			f(&o)
		}
	}
	_, system := o.clock.(clock.System)
	n := &Network{
		seed:     o.seed,
		clock:    o.clock,
		system:   system,
		base:     o.clock.Now(),
		coreHops: o.coreHops,
		queue:    inboxPackets,
		core:     &realm{owners: make(map[netip.Addr]any)},
		log:      newEventLog(o.eventLog),
		dns:      make(map[string][]netip.Addr),
		natNames: make(map[string]int),
	}
	n.coreLink = newLink(o.coreLink, &n.drops, n.rng("core-link", 0))
	n.sched = newScheduler(n)
	return n
}

// now returns the network time: the time elapsed since NewNetwork on the
// network's clock. Durations, not instants, keep the hot path free of
// wall-clock arithmetic and make dumps independent of when a test ran. On the
// system clock it reads only the monotonic clock, which is all the
// difference needs and halves the cost of the several readings per packet.
func (n *Network) now() time.Duration {
	if n.system {
		return time.Since(n.base)
	}
	return n.clock.Now().Sub(n.base)
}

// wall converts network time to an instant of the network's clock.
func (n *Network) wall(d time.Duration) time.Time { return n.base.Add(d) }

// until returns how long it is until t on the network's clock.
func (n *Network) until(t time.Time) time.Duration { return t.Sub(n.clock.Now()) }

// rng returns the random source of one component. Deriving every source from
// the seed and the component's identity keeps a component's draws independent
// of how much randomness the others consumed.
func (n *Network) rng(kind string, idx int) *rand.Rand {
	h := fnv.New64a()
	// Hash writes never fail.
	_, _ = h.Write([]byte(kind))
	var b [8]byte
	for i := range b {
		b[i] = byte(uint64(idx) >> (8 * i))
	}
	_, _ = h.Write(b[:])
	return rand.New(rand.NewPCG(uint64(n.seed), h.Sum64()))
}

// PublicHost attaches a host to the core. Without arguments it gets one public
// IPv4 and one public IPv6 address; pass netip.IPv4Unspecified() or
// netip.IPv6Unspecified() for an automatic address of one family, or explicit
// addresses. It panics if an explicit address is already in use.
func (n *Network) PublicHost(addrs ...netip.Addr) *Host {
	if len(addrs) == 0 {
		addrs = []netip.Addr{netip.IPv4Unspecified(), netip.IPv6Unspecified()}
	}
	return n.newHost(n.core, nil, addrs)
}

// NAT attaches a NAT device to the core. It panics on an invalid static
// configuration, such as an external address that is already in use.
func (n *Network) NAT(cfg NATConfig) *NAT { return n.newNAT(n.core, nil, cfg) }

// SetDNS makes [Host.LookupNetIP] resolve name to addrs on every host of the
// network; names are case-insensitive and a trailing dot is ignored. Calling
// it without addresses removes the name.
func (n *Network) SetDNS(name string, addrs ...netip.Addr) {
	key := dnsKey(name)
	n.topo.Lock()
	defer n.topo.Unlock()
	if len(addrs) == 0 {
		delete(n.dns, key)
		return
	}
	n.dns[key] = slices.Clone(addrs)
}

func dnsKey(name string) string { return strings.TrimSuffix(strings.ToLower(name), ".") }

func (n *Network) resolve(name string) []netip.Addr {
	n.topo.RLock()
	defer n.topo.RUnlock()
	return slices.Clone(n.dns[dnsKey(name)])
}

// Close shuts the network down. It stops the scheduler, waiting at most one
// second for its goroutine, drops the packets still in flight (counted as
// Dropped.Closed) and closes every socket and pipe. Objects created later are
// inert, and every method with an error result then returns an error
// wrapping net.ErrClosed; Stats and Dump keep working for post-mortems.
//
// Close is idempotent and safe for concurrent use: every caller waits for the
// first call and receives the same result, which is nil, the recovered panic
// of the scheduler goroutine, or an error saying that the goroutine did not
// stop in time.
func (n *Network) Close() error {
	n.closeOnce.Do(func() { n.closeErr = n.shutdown() })
	return n.closeErr
}

func (n *Network) shutdown() error {
	n.topo.Lock()
	n.closed.Store(true)
	hosts := slices.Clone(n.hosts)
	pipes := slices.Clone(n.pipes)
	n.topo.Unlock()

	dropped, err := n.sched.stop()
	n.drops.addN(dropClosed, uint64(dropped))
	// Closing a socket or pipe of the simulator cannot fail, so the
	// scheduler's error is the only one Close reports.
	for _, h := range hosts {
		h.Crash()
	}
	for _, p := range pipes {
		p.shutdown()
	}
	return err
}

// Stats returns a snapshot of the network-wide counters.
func (n *Network) Stats() NetStats {
	n.topo.RLock()
	hosts := slices.Clone(n.hosts)
	nats := slices.Clone(n.nats)
	n.topo.RUnlock()
	st := NetStats{
		PacketsSent:      n.sent.Load(),
		PacketsDelivered: n.delivered.Load(),
		Dropped:          n.drops.snapshot(),
		EventsScheduled:  n.sched.scheduled.Load(),
		EventsPending:    n.sched.pending(),
	}
	for _, nat := range nats {
		ns := nat.Stats()
		st.Dropped = st.Dropped.plus(ns.Dropped)
		st.FilteredInbound += ns.FilteredInbound
	}
	for _, h := range hosts {
		st.DroppedNoSocket += h.stats.noSocket.Load()
		st.DroppedInboxFull += h.stats.inboxFull.Load()
	}
	return st
}
