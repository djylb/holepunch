// Package probetest builds and reads the datagrams of a session client that
// probes natprobe observers, for tests that play that client by hand: the
// natprobe server's own tests and the coordinator's tests against a real
// natprobe. The client is written from the wire format, not from the
// library's prober, so it stays an independent check of both ends. It is
// test support only, never imported by library code.
package probetest

import "github.com/djylb/holepunch/internal/udpwire"

// Probe is one probe a client sends.
type Probe struct {
	Sandwich *[2]uint8 // round and phase of a SANDWICH TLV; nil sends none
	PlainLen int       // plaintext length passed to Seal; 0 is the codec's padding
	Seq      uint32    // 0 takes the codec's next seq
	Sock     uint8     // the client socket id
	Obs      uint8     // the observer id the probe is addressed to
	Extra    bool      // asks for the extra reply (FA)
	Alt      bool      // asks for the alternate reply (FB)
}

// Seal returns p sealed with the client codec c.
func Seal(c *udpwire.Codec, p Probe) ([]byte, error) {
	seq := p.Seq
	if seq == 0 {
		seq = c.NextSeq()
	}
	h := udpwire.Header{Type: udpwire.TProbe, Role: c.Role(), FA: p.Extra, FB: p.Alt, Sock: p.Sock, Cand: udpwire.NoCand,
		Aux: uint16(p.Obs), Seq: seq, TS: c.Now()}
	var tl udpwire.TLVs
	if p.Sandwich != nil {
		tl.Sandwich.Round, tl.Sandwich.Phase, tl.Sandwich.Set = p.Sandwich[0], p.Sandwich[1], true
	}
	return c.Seal(nil, &h, &tl, p.PlainLen)
}

// Open decodes a server reply b with the client codec c as a client's read
// pump does, using scratch (at least len(b) bytes) for the plaintext, and
// reports whether it is a valid reply for c's role.
func Open(c *udpwire.Codec, b, scratch []byte) (udpwire.Header, udpwire.TLVs, bool) {
	var h udpwire.Header
	var tl udpwire.TLVs
	ok := c.Open(b, scratch, &h, &tl) == udpwire.OK && c.CheckRole(&h) == udpwire.OK
	return h, tl, ok
}
