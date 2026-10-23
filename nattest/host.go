package nattest

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
)

// Ephemeral ports follow the Linux default range.
const (
	ephemeralLo = 32768
	ephemeralHi = 60999
)

// purposeListen labels the sockets opened with Host.Listen.
const purposeListen = "listen"

// Host is a simulated machine on the core or in a NAT's LAN. Its methods
// ListenPacket, InterfaceAddrs, OutboundAddr and LookupNetIP have the method
// set of holepunch.Network, so a *Host can be passed as Options.Network without
// an adapter; Listen has the signature of natprobe.ServerConfig.Listen. All
// methods are safe for concurrent use.
type Host struct {
	n        *Network
	name     string
	nat      *NAT
	realm    *realm
	addrs    []netip.Addr // IPv4 first; immutable
	prefixes []netip.Prefix
	inert    bool // created after Network.Close

	mu        sync.RWMutex           // guards the fields below
	ports     [2]map[uint16]*binding // [0] IPv4, [1] IPv6
	conns     map[*conn]struct{}
	pipes     map[*PipeConn]struct{}
	rng       *rand.Rand // ephemeral ports
	bindFail  map[string]*failRule
	writeFail map[string]*failRule

	anyWriteFail atomic.Bool // len(writeFail) > 0, read without mu on every write
	stats        hostCounters
}

// binding is what is bound to one port of one family: a wildcard socket, or
// sockets bound to specific addresses.
type binding struct {
	wild *conn
	byIP map[netip.Addr]*conn
}

func (n *Network) newHost(r *realm, nat *NAT, req []netip.Addr) *Host {
	n.topo.Lock()
	defer n.topo.Unlock()
	idx := len(n.hosts) + 1
	h := &Host{
		n: n, nat: nat, realm: r,
		conns:     make(map[*conn]struct{}),
		pipes:     make(map[*PipeConn]struct{}),
		rng:       n.rng("host", idx),
		bindFail:  make(map[string]*failRule),
		writeFail: make(map[string]*failRule),
	}
	h.ports[0] = make(map[uint16]*binding)
	h.ports[1] = make(map[uint16]*binding)
	h.stats.init()
	h.name = fmt.Sprintf("pub%d", idx)
	if nat != nil {
		h.name = fmt.Sprintf("%s.h%d", nat.name, idx)
	}
	if n.closed.Load() || (nat != nil && nat.inert) {
		h.inert = true
		return h
	}
	var want4, want6 int
	for _, a := range req {
		switch a = a.Unmap(); {
		case !a.IsValid():
		case a == netip.IPv4Unspecified():
			want4++
		case a == netip.IPv6Unspecified():
			want6++
		default:
			if !r.hasFamily(a.Is6()) {
				panic(fmt.Sprintf("nattest: %v: address family not available in this realm", a))
			}
			if n.ownedUp(r, a) != nil {
				panic(fmt.Sprintf("nattest: address %v already in use", a))
			}
			n.register(r, a, h)
			h.addrs = append(h.addrs, a)
		}
	}
	for _, auto := range [...]struct {
		v6 bool
		k  int
	}{{false, want4}, {true, want6}} {
		for range auto.k {
			if r.hasFamily(auto.v6) {
				a := n.allocAddr(r, auto.v6)
				n.register(r, a, h)
				h.addrs = append(h.addrs, a)
			}
		}
	}
	if len(h.addrs) == 0 {
		panic("nattest: host without address")
	}
	slices.SortStableFunc(h.addrs, func(a, b netip.Addr) int {
		switch {
		case a.Is4() == b.Is4():
			return 0
		case a.Is4():
			return -1
		}
		return 1
	})
	for _, a := range h.addrs {
		h.prefixes = append(h.prefixes, netip.PrefixFrom(a, n.prefixBits(r, a)))
	}
	n.hosts = append(n.hosts, h)
	return h
}

// Addrs returns the host's addresses, IPv4 first.
func (h *Host) Addrs() []netip.Addr { return slices.Clone(h.addrs) }

func (h *Host) owns(a netip.Addr) bool { return slices.Contains(h.addrs, a) }

func (h *Host) addrOf(v6 bool) netip.Addr {
	for _, a := range h.addrs {
		if a.Is6() == v6 {
			return a
		}
	}
	return netip.Addr{}
}

func (h *Host) families() uint8 {
	var m uint8
	for _, a := range h.addrs {
		m |= famBit(a.Is6())
	}
	return m
}

func (h *Host) isClosed() bool { return h.inert || h.n.closed.Load() }

// Conn is a socket of a Host: a net.PacketConn with the address-port calls,
// the hop limit (SetHopLimit, holepunch.HopLimiter) and the buffer sizes. It
// follows its deadlines on the network's clock.
type Conn interface {
	net.PacketConn
	ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error)
	WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error)
	SetHopLimit(hops int) error
	SetReadBuffer(bytes int) error
	SetWriteBuffer(bytes int) error
}

// ListenUDP opens a UDP socket. network is "udp", "udp4" or "udp6". A zero
// or unspecified laddr address binds every address of the family, dual
// stack for "udp"; port 0 picks a seeded ephemeral port in [32768, 60999].
// purpose is free text, normally a holepunch.Purpose* constant, that
// FailBinds, FailWrites and the statistics refer to. A canceled ctx fails
// the call.
func (h *Host) ListenUDP(ctx context.Context, network string, laddr netip.AddrPort, purpose string) (Conn, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, &net.OpError{Op: "listen", Net: network, Err: err}
		}
	}
	return h.listen(network, laddr, purpose)
}

// ListenPacket is ListenUDP with the signature of holepunch.Network: the
// returned conn is a Conn.
func (h *Host) ListenPacket(ctx context.Context, network string, laddr netip.AddrPort, purpose string) (net.PacketConn, error) {
	return h.ListenUDP(ctx, network, laddr, purpose)
}

// Listen is ListenUDP with the purpose "listen" and without a context. Its
// signature is that of natprobe.ServerConfig.Listen, so h.Listen can be
// injected there directly; the returned conn is a Conn.
func (h *Host) Listen(network string, laddr netip.AddrPort) (net.PacketConn, error) {
	return h.listen(network, laddr, purposeListen)
}

func (h *Host) listen(network string, laddr netip.AddrPort, purpose string) (Conn, error) {
	ip := laddr.Addr().Unmap()
	wild := !ip.IsValid() || ip.IsUnspecified()
	fail := func(err error) error {
		e := &net.OpError{Op: "listen", Net: network, Err: err}
		if laddr.IsValid() {
			e.Addr = net.UDPAddrFromAddrPort(laddr)
		}
		return e
	}
	if h.isClosed() {
		return nil, fail(net.ErrClosed)
	}
	fams, err := h.bindFamilies(network, ip, wild)
	if err != nil {
		return nil, fail(err)
	}
	if wild {
		ip = netip.Addr{}
	}
	h.mu.Lock()
	if h.n.closed.Load() {
		h.mu.Unlock()
		return nil, fail(net.ErrClosed)
	}
	if err := takeFail(h.bindFail, purpose); err != nil {
		h.mu.Unlock()
		h.stats.injectedBind.Add(1)
		return nil, fail(err)
	}
	port := laddr.Port()
	switch {
	case port == 0:
		port = h.ephemeralLocked(fams, ip)
		if port == 0 {
			h.mu.Unlock()
			return nil, fail(syscall.EADDRINUSE)
		}
	case !h.portFreeLocked(fams, ip, port):
		h.mu.Unlock()
		return nil, fail(syscall.EADDRINUSE)
	}
	c := &conn{
		h: h, purpose: purpose, fams: fams, ip: ip, port: port,
		inbox: make(chan *packet, h.n.queue), closing: make(chan struct{}),
		rd: newDeadline(), wd: newDeadline(),
	}
	for i := range h.ports {
		if fams&(1<<i) == 0 {
			continue
		}
		b := h.ports[i][port]
		if b == nil {
			b = &binding{}
			h.ports[i][port] = b
		}
		if !ip.IsValid() {
			b.wild = c
			continue
		}
		if b.byIP == nil {
			b.byIP = make(map[netip.Addr]*conn)
		}
		b.byIP[ip] = c
	}
	c.rec = h.stats.openSocket(c.localAP(), purpose)
	h.conns[c] = struct{}{}
	h.mu.Unlock()
	return c, nil
}

// bindFamilies returns the families a socket of network bound to ip covers.
func (h *Host) bindFamilies(network string, ip netip.Addr, wild bool) (uint8, error) {
	var fams uint8
	switch network {
	case "udp4":
		fams = famV4
	case "udp6":
		fams = famV6
	case "udp":
		switch {
		case wild && ip == netip.IPv4Unspecified():
			fams = famV4
		case wild:
			fams = (famV4 | famV6) & h.families() // dual stack where available
		case ip.Is4():
			fams = famV4
		default:
			fams = famV6
		}
	default:
		return 0, net.UnknownNetworkError(network)
	}
	switch {
	case !wild && (ip.Is6() != (fams == famV6)):
		return 0, syscall.EAFNOSUPPORT
	case wild && (fams == 0 || fams&h.families() != fams):
		return 0, syscall.EADDRNOTAVAIL
	case !wild && !h.owns(ip) && !ip.IsLoopback():
		return 0, syscall.EADDRNOTAVAIL
	}
	return fams, nil
}

func (h *Host) portFreeLocked(fams uint8, ip netip.Addr, port uint16) bool {
	for i := range h.ports {
		if fams&(1<<i) == 0 {
			continue
		}
		b := h.ports[i][port]
		switch {
		case b == nil:
		case b.wild != nil:
			return false
		case !ip.IsValid() && len(b.byIP) > 0:
			return false
		case ip.IsValid() && b.byIP[ip] != nil:
			return false
		}
	}
	return true
}

func (h *Host) ephemeralLocked(fams uint8, ip netip.Addr) uint16 {
	const size = ephemeralHi - ephemeralLo + 1
	for range 64 {
		p := uint16(ephemeralLo + h.rng.IntN(size))
		if h.portFreeLocked(fams, ip, p) {
			return p
		}
	}
	start := h.rng.IntN(size)
	for i := range size {
		p := uint16(ephemeralLo + (start+i)%size)
		if h.portFreeLocked(fams, ip, p) {
			return p
		}
	}
	return 0
}

func (h *Host) unbind(c *conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.conns, c)
	for i := range h.ports {
		if c.fams&(1<<i) == 0 {
			continue
		}
		b := h.ports[i][c.port]
		if b == nil {
			continue
		}
		if !c.ip.IsValid() {
			if b.wild == c {
				b.wild = nil
			}
		} else if b.byIP[c.ip] == c {
			delete(b.byIP, c.ip)
		}
		if b.wild == nil && len(b.byIP) == 0 {
			delete(h.ports[i], c.port)
		}
	}
}

// deliver queues p on the socket bound to its destination. The lookup and
// the queueing happen under one read lock: a socket's close unbinds it under
// the write lock before it drains its queue, so no packet is left behind in
// the queue of a closed socket.
func (h *Host) deliver(p *packet) {
	n := h.n
	size := uint64(len(p.data))
	why := dropNoSocket
	i := 0
	if p.dst.Addr().Is6() {
		i = 1
	}
	h.mu.RLock()
	if b := h.ports[i][p.dst.Port()]; b != nil {
		c := b.byIP[p.dst.Addr()]
		if c == nil {
			c = b.wild
		}
		if c != nil {
			// Logged first: once queued, p belongs to the reader.
			n.log.add(n, evDeliver, h.name, p, dropNone)
			why = c.enqueue(p)
		}
	}
	h.mu.RUnlock()
	switch why {
	case dropNone:
		h.stats.recv.Add(1)
		h.stats.bytesRecv.Add(size)
		n.delivered.Add(1)
		return
	case dropNoSocket:
		h.stats.noSocket.Add(1)
	default:
		h.stats.inboxFull.Add(1)
	}
	n.drop(p, h.name, why)
}

// InterfaceAddrs returns the host's one interface, "eth0" — an
// Ethernet-like link that is up — and its addresses with the prefix length
// of their network, IPv4 first.
func (h *Host) InterfaceAddrs() ([]net.Interface, [][]netip.Prefix, error) {
	if h.isClosed() {
		return nil, nil, &net.OpError{Op: "route", Net: "ip+net", Err: net.ErrClosed}
	}
	eth0 := net.Interface{Index: 1, MTU: 1500, Name: "eth0", Flags: net.FlagUp | net.FlagBroadcast | net.FlagMulticast | net.FlagRunning}
	return []net.Interface{eth0}, [][]netip.Prefix{slices.Clone(h.prefixes)}, nil
}

// OutboundAddr returns the source address the host uses towards the
// Internet. A network ending in "4" or "6" selects the family; otherwise
// ("udp", "ip") IPv4 is preferred.
func (h *Host) OutboundAddr(ctx context.Context, network string) (netip.Addr, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return netip.Addr{}, err
		}
	}
	if h.isClosed() {
		return netip.Addr{}, &net.OpError{Op: "dial", Net: network, Err: net.ErrClosed}
	}
	a := h.addrs[0]
	switch {
	case strings.HasSuffix(network, "6"):
		a = h.addrOf(true)
	case strings.HasSuffix(network, "4"):
		a = h.addrOf(false)
	}
	if !a.IsValid() {
		return netip.Addr{}, &net.OpError{Op: "dial", Net: network, Err: syscall.ENETUNREACH}
	}
	return a, nil
}

// LookupNetIP resolves address literals, "localhost" and the names
// registered with [Network.SetDNS]. network is "ip", "ip4" or "ip6"; a name
// without addresses of the requested family fails with a *net.DNSError whose
// IsNotFound is set.
func (h *Host) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if h.isClosed() {
		return nil, &net.OpError{Op: "lookup", Net: network, Err: net.ErrClosed}
	}
	var all []netip.Addr
	switch a, err := netip.ParseAddr(strings.Trim(host, "[]")); {
	case err == nil:
		all = []netip.Addr{a}
	case strings.EqualFold(host, "localhost"):
		all = []netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1}), netip.IPv6Loopback()}
	default:
		all = h.n.resolve(host)
	}
	var out []netip.Addr
	for _, a := range all {
		switch is4 := a.Unmap().Is4(); {
		case strings.HasSuffix(network, "4") && !is4:
		case strings.HasSuffix(network, "6") && is4:
		default:
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return out, nil
}

// Stats returns a snapshot of the host's counters.
func (h *Host) Stats() HostStats { return h.stats.snapshot(h.n) }

// OpenSockets returns the number of sockets that are not closed, for leak
// assertions.
func (h *Host) OpenSockets() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.conns)
}
