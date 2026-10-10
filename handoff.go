package holepunch

import (
	"time"

	"github.com/djylb/holepunch/internal/candidate"
	"github.com/djylb/holepunch/protocol"
)

// handoff is what finish hands to the Session: the sockets of the confirmed
// paths, each once — the primary path's first — with their port mappings,
// and the extra paths on them. Only finish uses
// it, on the caller's goroutine.
type handoff struct {
	socks []*handSock
	extra []handPath
}

// handSock is one socket to hand over.
type handSock struct {
	sock    *udpSock
	mapping *releaseCloser
	info    *protocol.PortMappingInfo
	owned   bool // disowned from the session group: finish closes it unless handed over
	lost    bool // an extra path's socket that failed a cleanup step: closed, its paths dropped
}

// handPath is an extra path and its socket.
type handPath struct {
	c candidate.Candidate
	s *handSock
}

// handoffOf collects the sockets of the primary path win and of the
// committed extra paths; nil when the primary path's socket is gone. An
// extra path whose socket is gone is left out.
func (rt *runtime) handoffOf(win *candidate.Action) *handoff {
	primary := rt.socks.byAddr(win.Local)
	if primary == nil {
		return nil
	}
	ho := &handoff{socks: []*handSock{{sock: primary}}}
	for _, c := range rt.punch.committedExtras() {
		s := rt.socks.byAddr(c.Local)
		if s == nil {
			continue
		}
		hs := ho.sockFor(s)
		if hs == nil {
			hs = &handSock{sock: s}
			ho.socks = append(ho.socks, hs)
		}
		ho.extra = append(ho.extra, handPath{c: c, s: hs})
	}
	return ho
}

func (ho *handoff) sockFor(s *udpSock) *handSock {
	for _, hs := range ho.socks {
		if hs.sock == s {
			return hs
		}
	}
	return nil
}

// disown moves every socket and its port mapping out of the session group
// and detaches it from the sender (finish step 1). The primary path's
// socket failing to detach fails the session; an extra path's is lost.
func (rt *runtime) disown(ho *handoff) *failure {
	for i, hs := range ho.socks {
		rt.g.Disown(hs.sock.conn)
		hs.owned = true
		if fs := rt.fam(hs.sock.fam); fs.primary == hs.sock && fs.mapping != nil {
			if info, rc, ok := fs.mapping.result(); ok {
				rt.g.Disown(rc)
				hs.mapping, hs.info = rc, &info
			}
		}
		if !hs.sock.detach() {
			if i == 0 {
				return fail(protocol.ReasonInternal, "write_stuck", nil)
			}
			rt.lose(hs)
		}
	}
	return nil
}

// stopReads interrupts the read loops of the sockets (finish step 2).
func (ho *handoff) stopReads(rt *runtime, f **failure) {
	for _, hs := range ho.socks {
		if !hs.lost {
			rt.step("finish.stopread", hs.sock.stopRead, f)
		}
	}
}

// joinReads waits for the sockets' read loops, all within winnerReadJoin
// (finish step 3). The library never hands out a socket it still
// reads: the primary path's stuck loop fails the session, an extra path's
// loses that socket.
func (rt *runtime) joinReads(ho *handoff) *failure {
	t := time.NewTimer(winnerReadJoin)
	defer t.Stop()
	expired := false
	for i, hs := range ho.socks {
		if hs.lost {
			continue
		}
		done := false
		if !expired {
			select {
			case <-hs.sock.readDone:
				done = true
			case <-t.C:
				expired = true
			}
		}
		if !done {
			select {
			case <-hs.sock.readDone:
				done = true
			default:
			}
		}
		switch {
		case done:
		case i == 0:
			return fail(protocol.ReasonInternal, "readloop_stuck", nil)
		default:
			rt.lose(hs)
		}
	}
	return nil
}

// restore clears the sockets' deadlines and restores their TTL: the
// library's last touch of each (finish step 4).
func (ho *handoff) restore(rt *runtime, f **failure) {
	for _, hs := range ho.socks {
		if hs.lost {
			continue
		}
		s := hs.sock
		rt.step("finish.restore", func() {
			_ = s.conn.SetReadDeadline(time.Time{})
			_ = s.conn.SetWriteDeadline(time.Time{})
			if s.curHop != 0 {
				_ = s.hop.set(0)
			}
		}, f)
	}
}

// lose closes an extra path's socket that cannot be handed over, and its
// port mapping; the paths on it are dropped.
func (rt *runtime) lose(hs *handSock) {
	hs.lost = true
	rt.closeHanded(hs)
}

// closeAll closes every socket finish took out of the session group: the
// session failed after step 1, and nothing else would ever close them.
func (rt *runtime) closeAll(ho *handoff) {
	for _, hs := range ho.socks {
		if hs.owned && !hs.lost {
			hs.lost = true
			rt.closeHanded(hs)
		}
	}
}

func (rt *runtime) closeHanded(hs *handSock) {
	var f *failure
	rt.step("finish.closewinner", func() {
		_ = hs.sock.conn.Close()
		if hs.mapping != nil {
			_ = hs.mapping.Close()
		}
	}, &f)
}

// paths returns the extra paths whose sockets are handed over.
func (ho *handoff) paths() []handPath {
	var out []handPath
	for _, p := range ho.extra {
		if !p.s.lost {
			out = append(out, p)
		}
	}
	return out
}
