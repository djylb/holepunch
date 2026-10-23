package udpwire

import (
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/internal/netaddr"
)

// DropResidual wraps pc, a handed-over socket given to a non-QUIC upper layer
// on the listening side (e.g. kcp-go ServeConn), so that late holepunch
// packets — the initiator's ready retransmissions and other handshake
// stragglers — never reach that layer, which would otherwise mistake them for
// new sessions. QUIC upper layers need no wrapper: quic-go discards
// first bytes in [B0Min, B0Max] by itself.
//
// For window after the call (DefaultResidualWindow if window ≤ 0), a datagram
// from one of codec.Peers() — the remotes of every confirmed path, so one
// filter serves each handed-over socket; any source while none is bound — whose
// length and first byte pass Precheck — directly, or inside an opener (Unwrap)
// — is trial-opened with the session AEAD — verification only, into a private
// buffer, so the caller's bytes are untouched. If it authenticates it is
// dropped, counted, and ReadFrom reads the next one; every other datagram is
// returned unchanged. An upper-layer packet is dropped only if it forges a GCM
// tag (≈ 2⁻¹²⁸). After the window ReadFrom costs one atomic load more than
// pc's. The wrapper starts no goroutine and never touches deadlines, so a read
// deadline set by the caller bounds the whole ReadFrom.
//
// The returned conn also has a Dropped() uint64 method reporting the residuals
// dropped so far (reach it with an interface assertion). All other methods are
// pc's own; closing the wrapper closes pc. DropResidual returns pc itself when
// pc or codec is nil.
func DropResidual(pc net.PacketConn, codec *Codec, window time.Duration) net.PacketConn {
	if pc == nil || codec == nil {
		return pc
	}
	if window <= 0 {
		window = DefaultResidualWindow
	}
	return &residualConn{PacketConn: pc, codec: codec, until: codec.now().Add(window)}
}

// residualConn is the DropResidual wrapper.
type residualConn struct {
	net.PacketConn
	codec   *Codec
	until   time.Time
	expired atomic.Bool // set once the window has passed; skips the clock
	dropped atomic.Uint64

	mu      sync.Mutex // guards scratch across concurrent readers
	scratch [MaxPlaintext]byte
}

// ReadFrom reads the next datagram that is not a holepunch residual.
func (r *residualConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, from, err := r.PacketConn.ReadFrom(p)
		if err != nil || !r.residual(p[:n], from) {
			return n, from, err
		}
		r.dropped.Add(1)
	}
}

// Dropped returns the number of residual datagrams dropped so far.
func (r *residualConn) Dropped() uint64 { return r.dropped.Load() }

// residual reports whether pkt, received from from within the window, is an
// authentic packet of the session from a confirmed path's remote.
func (r *residualConn) residual(pkt []byte, from net.Addr) bool {
	if r.expired.Load() {
		return false
	}
	if !r.codec.now().Before(r.until) {
		r.expired.Store(true)
		return false
	}
	if Wrapped(pkt) {
		inner, e := Unwrap(pkt)
		if e != OK {
			return false
		}
		pkt = inner
	}
	if Precheck(pkt, MinPeerPacket) != OK {
		return false
	}
	if peers := r.codec.peers.Load(); peers != nil {
		if src, ok := netaddr.FromNetAddr(from); !ok || !slices.Contains(*peers, src) {
			return false
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.codec.decrypt(pkt, PeerOuterSize, r.scratch[:])
	return ok
}
