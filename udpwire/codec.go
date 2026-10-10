package udpwire

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"math/rand/v2"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Codec seals and opens one session's packets for one role. Clients create it
// on punch_start and natprobe on Registry.Register (role RoleServer); the key
// is derived once and every later operation reuses it. A Codec is safe for
// concurrent use and must be created with NewCodec.
type Codec struct {
	route [RouteSize]byte
	role  Role
	pad   PadPolicy
	now   func() time.Time
	t0    time.Time
	aead  cipher.AEAD

	// aad holds b0 ‖ route for each of the 12 possible first bytes. The AEAD
	// takes the AAD through an interface call, so a per-call stack buffer
	// would escape to the heap; this read-only table keeps Seal and Open
	// allocation-free and is shared by concurrent calls without locking.
	aad [b0Count][1 + RouteSize]byte

	seq   atomic.Uint32
	peers atomic.Pointer[[]netip.AddrPort]

	mu sync.Mutex
	// nonces is a ChaCha8 CSPRNG seeded from crypto/rand. A fresh random
	// seed per Codec means a re-created codec never repeats a nonce under the
	// same key; the nonce is not a counter because an incrementing field
	// would let observers link a session's packets. Reading
	// crypto/rand per packet instead costs a global lock on some platforms.
	nonces *rand.ChaCha8
	// pacer is the PacerSeed stream: b0 and packet lengths. Neither is
	// secret, but they are unpredictable without the token.
	pacer *rand.Rand
}

// NewCodec derives the session key and prepares a codec for role. pad is the
// session's client-to-client length interval: clients pass punch_start.wire,
// clamped to the protocol bounds (the zero value is an error), and natprobe
// passes the zero value, which it never uses. now is the clock (nil means
// time.Now); see Codec.Now.
func NewCodec(token [32]byte, route [RouteSize]byte, role Role, pad PadPolicy, now func() time.Time) (*Codec, error) {
	if role < RoleInitiator || role > RoleServer {
		return nil, errBadRole
	}
	if role == RoleServer {
		pad = PadPolicy{}
	} else {
		var err error
		if pad, err = pad.clamp(); err != nil {
			return nil, err
		}
	}
	if now == nil {
		now = time.Now
	}
	key := aeadKey(token, route)
	block, err := aes.NewCipher(key[:])
	clear(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	var nonceSeed [32]byte
	// Since Go 1.24 crypto/rand.Read never returns an error: it aborts the
	// process if the OS cannot supply randomness.
	_, _ = crand.Read(nonceSeed[:])
	c := &Codec{
		route:  route,
		role:   role,
		pad:    pad,
		now:    now,
		t0:     now(),
		aead:   aead,
		nonces: rand.NewChaCha8(nonceSeed),
		pacer:  rand.New(rand.NewChaCha8(PacerSeed(token, route, role))),
	}
	clear(nonceSeed[:])
	for i := range c.aad {
		c.aad[i][0] = B0Min + byte(i)
		copy(c.aad[i][1:], route[:])
	}
	return c, nil
}

// NextSeq returns the next sequence number of this codec, starting at 1. It
// is shared by every socket and address family of the session, so the first
// seq seen per observer orders mapping creation. A session sends at most
// 40 000 packets, far from wrapping.
func (c *Codec) NextSeq() uint32 { return c.seq.Add(1) }

// Now returns the header timestamp: for clients the milliseconds since
// NewCodec on the session's monotonic time axis (used for zero-state RTT via
// EchoTS); for natprobe Unix milliseconds mod 2³², a diagnostic only. No
// protocol decision depends on wall-clock time.
func (c *Codec) Now() uint32 {
	t := c.now()
	if c.role == RoleServer {
		return uint32(t.UnixMilli())
	}
	d := t.Sub(c.t0)
	if d < 0 {
		return 0
	}
	return uint32(d / time.Millisecond)
}

// BindPeers records the remote addresses of the session's confirmed paths at
// handover, the primary path's first; DropResidual
// then inspects only datagrams from them. The addresses are stored unmapped
// and without a zone, the form in which they are compared. A later call
// replaces the set.
func (c *Codec) BindPeers(ps ...netip.AddrPort) {
	set := make([]netip.AddrPort, len(ps))
	for i, p := range ps {
		set[i] = canonical(p)
	}
	c.peers.Store(&set)
}

// Role returns the role the codec was created for: the sender role written
// into every header it seals and the peer of the role CheckRole accepts.
func (c *Codec) Role() Role { return c.role }

// Peers returns a copy of the addresses recorded by BindPeers (canonical
// form), or nil before handover.
func (c *Codec) Peers() []netip.AddrPort {
	if p := c.peers.Load(); p != nil {
		return append([]netip.AddrPort(nil), *p...)
	}
	return nil
}

// CheckRole performs the header-only part of the role check
// for a header returned by Open or OpenProbe on this codec. natprobe accepts
// only probes from a client. A client accepts replies only from the server,
// hairpin only from itself, and punch, success and handshake packets only
// from the other client; anything else — its own packets reflected back,
// loopback, a probe — is ErrRole. Source-address checks and the hairpin
// pending set are the caller's. A header with an invalid type is ErrPayload.
func (c *Codec) CheckRole(h *Header) DecodeError {
	r, ok := ruleOf(h.Type)
	if !ok {
		return ErrPayload
	}
	var want roleSet
	switch {
	case c.role == RoleServer:
		if h.Type == TProbe {
			want = fromClient
		}
	case h.Type == TProbe:
		// Clients never receive probes.
	case r.senders == fromServer:
		want = fromServer
	case h.Type == THairpin:
		want = roleBit(c.role)
	default:
		want = roleBit(peerOf(c.role))
	}
	if (want & r.senders).has(h.Role) {
		return OK
	}
	return ErrRole
}
