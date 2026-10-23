package nattest

import (
	"net"
	"net/netip"
	"syscall"
)

// failRule is an injected failure of binds or writes of one purpose.
type failRule struct {
	left int // calls still to fail; < 0 until cleared
	err  error
}

// takeFail consumes one failure for purpose, falling back to the rule for
// every purpose (""); the caller holds the host's mu.
func takeFail(rules map[string]*failRule, purpose string) error {
	key := purpose
	r := rules[key]
	if r == nil {
		key = ""
		r = rules[key]
	}
	if r == nil {
		return nil
	}
	if r.left > 0 {
		r.left--
		if r.left == 0 {
			delete(rules, key)
		}
	}
	return r.err
}

func (h *Host) takeWriteFail(purpose string) error {
	if !h.anyWriteFail.Load() {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	err := takeFail(h.writeFail, purpose)
	h.anyWriteFail.Store(len(h.writeFail) > 0)
	return err
}

// FailWrites makes the next n writes on sockets of the given purpose ("" for
// any purpose) fail with err, by default EPERM; ENOBUFS is the other
// realistic choice. A negative n fails every write until FailWrites(purpose,
// 0, nil) clears the rule. Failed writes send nothing and are counted in
// HostStats.InjectedWriteErrors.
func (h *Host) FailWrites(purpose string, n int, err error) {
	if err == nil {
		err = syscall.EPERM
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if n == 0 {
		delete(h.writeFail, purpose)
	} else {
		h.writeFail[purpose] = &failRule{left: n, err: err}
	}
	h.anyWriteFail.Store(len(h.writeFail) > 0)
}

// FailBinds makes the next n ListenPacket or Listen calls of the given
// purpose ("" for any purpose) fail with EADDRINUSE. A negative n fails every
// bind until FailBinds(purpose, 0) clears the rule.
func (h *Host) FailBinds(purpose string, n int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if n == 0 {
		delete(h.bindFail, purpose)
		return
	}
	h.bindFail[purpose] = &failRule{left: n, err: syscall.EADDRINUSE}
}

// Crash closes every socket and every pipe end of the host at once, as if
// its process died: blocked calls return net.ErrClosed and pipe peers read
// EOF after the one-way delay. The host can open sockets again afterwards,
// like a restarted process.
func (h *Host) Crash() {
	h.mu.Lock()
	conns := make([]*conn, 0, len(h.conns))
	for c := range h.conns {
		conns = append(conns, c)
	}
	pipes := make([]*PipeConn, 0, len(h.pipes))
	for p := range h.pipes {
		pipes = append(pipes, p)
	}
	h.mu.Unlock()
	for _, c := range conns {
		_ = c.close() // only fails when closed concurrently
	}
	for _, p := range pipes {
		_ = p.Close()
	}
}

// MarkHandover marks the open socket bound to local as handed over to the
// application: the socket that receives packets sent to local. An
// unspecified or invalid address matches any socket on that port, the
// wildcard socket first, then the one bound to the lowest address, in the
// unspecified address's family first. From then on every call made on it,
// except through the returned conn, is counted in
// HostStats.WritesAfterHandover: the library must not touch the socket
// after it returned it. The application uses the returned conn, which has
// the same methods as the socket. The lookup is by address, so the mark
// works even when the library handed the socket out wrapped in its own
// conn.
func (h *Host) MarkHandover(local netip.AddrPort) (Conn, error) {
	fail := func(err error) error {
		return &net.OpError{Op: "handover", Net: "udp", Addr: net.UDPAddrFromAddrPort(local), Err: err}
	}
	if h.isClosed() {
		return nil, fail(net.ErrClosed)
	}
	h.mu.RLock()
	found := h.boundLocked(local.Addr().Unmap(), local.Port())
	h.mu.RUnlock()
	if found == nil {
		return nil, fail(syscall.ENOENT)
	}
	found.handover.Store(true)
	h.stats.markHandover(found.rec)
	return callerConn{found}, nil
}

// boundLocked returns the socket MarkHandover means by ip and port; h.mu is
// held.
func (h *Host) boundLocked(ip netip.Addr, port uint16) *conn {
	fams := [2]int{0, 1}
	if ip.Is6() {
		fams = [2]int{1, 0}
	}
	for _, i := range fams {
		b := h.ports[i][port]
		switch {
		case b == nil:
		case ip.IsValid() && !ip.IsUnspecified():
			if (i == 1) != ip.Is6() {
				continue
			}
			if c := b.byIP[ip]; c != nil {
				return c
			}
			if b.wild != nil {
				return b.wild
			}
		case b.wild != nil:
			return b.wild
		default:
			var lowest *conn
			for a, c := range b.byIP {
				if lowest == nil || a.Less(lowest.ip) {
					lowest = c
				}
			}
			if lowest != nil {
				return lowest
			}
		}
	}
	return nil
}
