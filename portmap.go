package holepunch

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/protocol"
)

// PortMapper creates port mappings (UPnP, NAT-PMP, PCP) for a session's
// primary sockets. Pass portmapper.New(...) in Options.PortMapper to enable
// it; the root package itself never links a port-mapping implementation.
type PortMapper interface {
	// Map requests an external mapping for conn's local port. release must
	// be idempotent, stop any renewal and delete the mapping, and return
	// within 2 s. Map must honour ctx. conn is the session's own socket,
	// passed only so that Map can read its LocalAddr.
	Map(ctx context.Context, conn net.PacketConn, policy protocol.PortMappingPolicy) (info protocol.PortMappingInfo, release func() error, err error) //holepunch:callback
}

// portMapBudget bounds a mapping attempt: it runs alongside probing
// and never holds up probe_report; a late result goes into punch_ready.
const portMapBudget = 2500 * time.Millisecond

// Fault-injection point names (internal/faultinject; string constants so the
// default build compiles the calls away).
const fiPortmapMap = "portmap.map"

// portMapping is the mapping attempt of one family's primary socket. The
// socket keeps no wrapper: the session group owns the release of
// a losing socket's mapping, and the winning one moves to Session.Close.
type portMapping struct {
	sock *udpSock

	mu       sync.Mutex
	done     bool
	ok       bool
	info     protocol.PortMappingInfo
	closer   *releaseCloser
	reported bool // already sent in probe_report or punch_ready
}

// result returns the finished mapping, if any.
func (m *portMapping) result() (protocol.PortMappingInfo, *releaseCloser, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.info, m.closer, m.done && m.ok
}

// takeReport returns the wire form of a finished mapping the first time it is
// asked for, so a mapping is reported once: in probe_report when it finished
// before, in punch_ready when it finished later.
func (m *portMapping) takeReport() *protocol.PortMapReport {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.done || !m.ok || m.reported {
		return nil
	}
	m.reported = true
	r := m.info.Report()
	return &r
}

// releaseCloser adapts a mapping's release function to io.Closer for the
// session group; it is idempotent on its own, whatever the mapper does.
type releaseCloser struct {
	once    sync.Once
	release func() error
	err     error
}

func (r *releaseCloser) Close() error {
	r.once.Do(func() {
		if p := life.Safe("portmap.release", func() { r.err = r.release() }); p != nil {
			r.err = p
		}
	})
	return r.err
}

// startPortMap runs the mapping attempt of sock in a session goroutine.
func (rt *runtime) startPortMap(sock *udpSock, policy protocol.PortMappingPolicy) *portMapping {
	m := &portMapping{sock: sock}
	name := "portmap:" + string(sock.fam)
	started := rt.g.Go(name, func(gctx context.Context) {
		ctx, cancel := context.WithCancel(gctx)
		defer cancel()
		t := rt.clk.AfterFunc(portMapBudget, cancel)
		defer t.Stop()
		var (
			info    protocol.PortMappingInfo
			release func() error
			err     error
		)
		if err = faultinject.Point(fiPortmapMap); err == nil {
			if p := life.Safe("portmap.map", func() { info, release, err = rt.mapper.Map(ctx, sock.conn, policy) }); p != nil {
				err = p
				rt.cnt.callbackPanics.Add(1)
			}
		}
		ok := err == nil && release != nil
		var rc *releaseCloser
		if ok {
			rc = &releaseCloser{release: release}
			if !rt.g.Own(name, rc) {
				ok = false // the session is closing; Own released the mapping
			}
		}
		m.mu.Lock()
		m.done, m.ok, m.info, m.closer = true, ok, info, rc
		m.mu.Unlock()
		status, detail := protocol.StatusOK, string(info.Method)
		if !ok {
			status, detail = protocol.StatusFail, ""
		}
		rt.progress(progressEvent{stage: stagePortmapReady, status: status, detail: detail, family: sock.fam})
	})
	if !started {
		m.done = true
	}
	return m
}
