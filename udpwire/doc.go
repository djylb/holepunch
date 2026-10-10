// Package udpwire encodes and decodes holepunch UDP packets: the punch,
// nomination and handover packets that clients exchange with each other, the
// probes clients send to natprobe, and natprobe's replies.
//
// # Wire format
//
// Every packet is authenticated and encrypted with the session's
// AES-256-GCM key, HKDF-SHA256(token, salt=route, "holepunch/1 udp aead").
// The protocol major version lives only in that info string, so a packet from
// another major version fails authentication like any foreign packet. There
// are two envelopes, chosen by the receiver rather than marked on the wire:
//
//	envelope S (everything except probes)  b0 | nonce12 | ciphertext | tag16
//	envelope P (probe, client → natprobe)  b0 | nonce12 | mroute16 | ciphertext | tag16
//
// b0 is drawn per packet from [B0Min, B0Max] and the nonce is fresh CSPRNG
// output, so no byte position is constant within a session. The route never
// travels in clear: envelope S omits it (the receiving socket belongs to one
// session) and envelope P carries it masked with SHA-256 of the nonce so that
// natprobe can find the session before decrypting. The AAD is b0 ‖ route in
// both envelopes. Inside the ciphertext is a fixed 24-byte [Header], then the
// TLVs the packet type carries ([TLVs]), then zero padding up to a length
// drawn from the session's [PadPolicy] or the probe interval.
//
// The first datagram a socket sends to each remote endpoint travels as an
// opener instead: [Codec.Wrap] puts the sealed
// packet into a standard STUN Binding Request, as the value of a PADDING
// attribute followed by FINGERPRINT, for networks that cut a UDP flow whose
// first five datagrams hold no STUN message. A first byte in [0, 3] marks
// the STUN range of RFC 7983 ([Wrapped]); [Unwrap] returns the packet
// inside, which then goes through the pipeline below like any other.
//
// # Receive pipeline
//
// Callers run, in order: [Unwrap] for a datagram in the STUN range, [Precheck]
// (length and b0, no cryptography), their
// own pre-AEAD rate limit, [Codec.Open] or [Codec.OpenProbe] (decrypt and
// parse), [Codec.CheckRole] (sender role relative to the receiver), and
// [SeqWindow.Accept] (replay). Each stage reports a [DecodeError] whose
// String is the drop-counter key; failed packets are never answered.
// natprobe calls [UnmaskRoute] before [Codec.OpenProbe] to find the session.
//
// # Concurrency
//
// A [Codec] is safe for concurrent use. Seal holds a per-codec mutex only
// while drawing b0, the packet length and the nonce, Wrap while drawing the
// transaction id; decryption, parsing,
// CheckRole and NextSeq take no lock. A [SeqWindow] is not safe for concurrent
// use: its owner serializes Accept. The connection returned by [DropResidual]
// is safe for concurrent use, like any [net.PacketConn].
//
// # Resource ownership
//
// The package starts no goroutines and opens no sockets. A Codec holds only
// memory (key schedule, two ChaCha8 states) and needs no Close. Seal and Wrap
// append to the caller's buffer, Open decrypts into the caller's scratch
// buffer or in place and Unwrap returns a subslice of its input; none
// retains a reference after returning. DropResidual wraps
// a connection it does not own: closing the wrapper closes the wrapped
// connection, exactly as the caller would.
package udpwire
