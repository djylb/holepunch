package holepunch

import (
	"net/netip"
	"sync/atomic"

	"github.com/djylb/holepunch/udpwire"
)

// The flow opener. Some
// networks cut a UDP flow — local socket × remote endpoint — after its fifth
// datagram unless one of the first five is a STUN message. So the first
// datagram a socket writes to each remote goes out as a STUN Binding Request
// carrying the sealed packet (udpwire.Codec.Wrap): probes to the observers,
// punches, replies, handshake and handover packets alike, without adding a
// packet. Later datagrams of the flow keep the plain sealed form.
//
// A flow counts as opened only once a datagram left on it at the normal
// TTL: a low-TTL packet dies before it reaches the peer and may die before
// a classifier on the way, so the next datagram of the flow opens it again.
// A third party's STUN request is a STUN message already and opens its flow
// as it is.

// maxOpenFlows bounds the flows a session remembers as opened, across its
// sockets, closed ones included. A session sends at most a few thousand
// initiated packets, so the bound is not reached in practice; beyond it a
// socket keeps sending openers to remotes it cannot remember, which costs
// only their bytes: every receiver accepts both forms.
const maxOpenFlows = 4096

// opener is the session's flow opener, shared by its sockets. Each socket
// keeps its own set of opened remotes under its write turn; the opener only
// wraps and counts how many remotes the sockets remember.
type opener struct {
	codec *udpwire.Codec
	flows atomic.Int32
}

func newOpener(codec *udpwire.Codec) *opener { return &opener{codec: codec} }

// form returns the datagram to write for pkt toward to: pkt itself on a
// flow the socket has opened (or for a STUN message of the prober's), else
// its opener in the socket's buffer. The caller holds the write turn.
func (s *udpSock) form(pkt []byte, to netip.AddrPort) (out []byte, wrapped bool) {
	if s.op == nil || udpwire.Wrapped(pkt) {
		return pkt, false
	}
	if _, ok := s.opened[to]; ok {
		return pkt, false
	}
	if s.obuf == nil {
		s.obuf = make([]byte, 0, udpwire.MaxWrapped)
	}
	s.obuf = s.op.codec.Wrap(s.obuf[:0], pkt)
	return s.obuf, true
}

// noteOpened records that a datagram left toward to at the normal TTL, which
// opens the flow, within the session's bound. The caller holds the write
// turn.
func (s *udpSock) noteOpened(to netip.AddrPort) {
	if s.op == nil {
		return
	}
	if _, ok := s.opened[to]; ok {
		return
	}
	if s.op.flows.Add(1) > maxOpenFlows {
		s.op.flows.Add(-1)
		return
	}
	if s.opened == nil {
		s.opened = map[netip.AddrPort]struct{}{}
	}
	s.opened[to] = struct{}{}
}
