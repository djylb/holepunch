package holepunch

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// The run guard is the part of the send gate that keeps a hard limit: in
// the sequence of packets that leave
// towards one IP, at most three consecutive destination ports, ascending or
// descending. A repeated port neither extends nor breaks a run; a pause of
// portWindow (the 10 s window of the other per-IP limits) starts a new
// one.
//
// The plan cannot keep the limit on its own. internal/plan expands each
// predict or random stage with runs of at most three, but the packets that
// actually leave towards one IP interleave several streams — the Direct
// repeats on their own offsets, the spray of each stage in turn, pushed
// peer_targets and their port windows, follow-ups, and the replies and
// handshake packets of other goroutines — and the seams form runs that no
// single expansion contains: a predict spray around an anchor P that ends
// P-3, P-2, P-1 just before the Direct repeat to P. The guard therefore
// judges each packet against the run its IP's sequence ends with, in the
// order the packets are written: a family's writes pass one at a time
// through its lane, from the run check to the write.
//
// How far a packet may extend a run:
//   - an answer — a success reply or a handshake packet — to three: it goes
//     to an address a valid packet came from, and the session needs it;
//   - any packet the session opens on its own (punches, follow-ups,
//     peer_targets, the hairpin probe) to two, so that the third port of a
//     run is always an answer's; and not even to two when the run would
//     then point at a known port — a Direct target of the round or an
//     address that answered — unless the packet's own port is known, so that
//     blind spraying never parks a run in front of the ports that matter.
//
// A packet that would go further is held back (errRun) and nothing of the
// budget is spent on it: the round goroutine sends it after another packet
// broke the run, a follow-up skips it, a reply or handshake packet is
// dropped (the peer repeats its punch, the state machine resends). Since the
// third port of every run is an answer's, an answer is only held back next
// to another address that answered, which the nomination can use instead.
//
// Packets to natprobe's observers are recorded but never held back: the
// observers sit on consecutive ports by design (p2p_port..p2p_port+2) and
// are the server's, not the peer's.

// Run limits.
const (
	maxAnswerRun = 3 // the hard limit, which an answer may reach
	maxOpenRun   = 2 // what a packet the session opens may bring a run to
)

var errRun = errors.New("holepunch: held back: consecutive ports")

// portRun is the run of consecutive destination ports that the send
// sequence towards one IP ends with.
type portRun struct {
	last uint16
	dir  int       // +1 or -1 once the run has two ports
	n    int       // ports in the run; 0 before the first packet
	at   time.Time // when the last packet left
}

// then is the run after a packet to port at now.
func (r portRun) then(port uint16, now time.Time) portRun {
	d := int(port) - int(r.last)
	switch {
	case r.n == 0 || now.Sub(r.at) >= portWindow:
		return portRun{last: port, n: 1, at: now}
	case d == 0:
		r.at = now
		return r
	case d == 1 || d == -1:
		if r.n >= 2 && d == r.dir {
			return portRun{last: port, dir: d, n: r.n + 1, at: now}
		}
		return portRun{last: port, dir: d, n: 2, at: now}
	}
	return portRun{last: port, n: 1, at: now}
}

// lane serialises one family's writes from the run check to the write, so
// that the recorded runs follow the order in which the packets leave. A
// send holds it while it waits for its rate tokens, too: the packets of one
// family leave one at a time at that rate anyway, and the order is decided
// by the check.
type lane struct {
	turn chan struct{}
	runs map[netip.Addr]portRun // guarded by turn
}

func newLane() *lane { return &lane{turn: make(chan struct{}, 1), runs: map[netip.Addr]portRun{}} }

// acquire takes the lane; it fails when ctx ends first.
func (l *lane) acquire(ctx context.Context) error {
	select {
	case l.turn <- struct{}{}:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func (l *lane) release() { <-l.turn }

// wrote records a packet written to `to` at now.
func (l *lane) wrote(to netip.AddrPort, now time.Time) {
	ip := to.Addr()
	l.runs[ip] = l.runs[ip].then(to.Port(), now)
}

// runAllows reports whether a packet of class o.class to `to` may leave now
// without extending the run of its IP further than the class may (see the
// rules above). The caller holds l.
func (s *sender) runAllows(l *lane, to netip.AddrPort, o *sendOpt, now time.Time) bool {
	if s.rt.isObserver(to) {
		return true
	}
	cur := l.runs[to.Addr()]
	next := cur.then(to.Port(), now)
	switch {
	case next.n == 1 || to.Port() == cur.last:
		return true // a new run, or a repeat
	case o.class == classReply || o.class == classHandshake:
		return next.n <= maxAnswerRun
	case next.n > maxOpenRun:
		return false
	}
	c := int(to.Port()) + next.dir
	return c < 1 || c > 0xFFFF || s.known(to, o) || !s.known(netip.AddrPortFrom(to.Addr(), uint16(c)), o)
}

// known reports whether ap is a Direct target of the packet's round or an
// address that answered.
func (s *sender) known(ap netip.AddrPort, o *sendOpt) bool {
	return o.round != nil && o.round.direct[ap] || s.rt.punch.isHit(ap)
}
