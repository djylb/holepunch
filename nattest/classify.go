package nattest

import (
	"encoding/binary"
	"net/netip"
	"time"
)

// stunMagic is the magic cookie of RFC 8489, section 5.
const stunMagic = 0x2112A442

// IsSTUN reports whether payload is a STUN message by its header, the way
// a protocol classifier recognises one (RFC 8489, section 5): the two top bits
// clear, the magic cookie at offset 4 and a message length that covers the
// rest of the datagram in whole 32-bit words.
func IsSTUN(payload []byte) bool {
	if len(payload) < 20 || payload[0]&0xC0 != 0 || binary.BigEndian.Uint32(payload[4:]) != stunMagic {
		return false
	}
	n := int(binary.BigEndian.Uint16(payload[2:]))
	return n%4 == 0 && 20+n == len(payload)
}

// flowKey is one flow the classifier follows: a translated source endpoint
// and a destination.
type flowKey struct{ src, dst netip.AddrPort }

// classFlow is the classifier's state of one flow.
type classFlow struct {
	seen    int  // datagrams inspected
	allowed bool // one of them was allowed: the flow passes for good
	last    time.Duration
}

// minClassFlows is the size below which the classifier's flow table is not
// swept; it then sweeps whenever it has doubled.
const minClassFlows = 256

// classifyLocked runs the device's Classifier on a datagram leaving through
// the uplink from src (translated) to dst, and reports whether it passes.
// The caller holds nat.mu.
func (nat *NAT) classifyLocked(src, dst netip.AddrPort, payload []byte, now time.Duration) bool {
	c := nat.cfg.Classifier
	k := flowKey{src, dst}
	f := nat.flows[k]
	if f == nil || !nat.fresh(f.last, now) {
		if f == nil {
			nat.sweepFlowsLocked(now)
		}
		f = &classFlow{}
		nat.flows[k] = f
	}
	f.last = now
	switch {
	case f.allowed:
		return true
	case f.seen >= c.Window:
		return false
	}
	f.seen++
	f.allowed = c.Allow(payload)
	return true
}

// sweepFlowsLocked drops the flows idle for MappingTimeout once the table
// has doubled since the last sweep, so that it stays bounded by the flows
// of one timeout.
func (nat *NAT) sweepFlowsLocked(now time.Duration) {
	if nat.flows == nil {
		nat.flows, nat.flowCap = map[flowKey]*classFlow{}, minClassFlows
		return
	}
	if len(nat.flows) < nat.flowCap {
		return
	}
	for k, f := range nat.flows {
		if !nat.fresh(f.last, now) {
			delete(nat.flows, k)
		}
	}
	nat.flowCap = max(2*len(nat.flows), minClassFlows)
}
