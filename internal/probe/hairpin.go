package probe

import (
	"context"
	"slices"

	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/udpwire"
)

// Hairpin runs the hairpin self-test: the primary
// socket sends two hairpin packets 100 ms apart to its own observed address
// and waits until 250 ms after the first for one of them to come back on the
// same socket (the read pump has checked that the sender role is our own).
// It returns True (High), False (Medium: both lost) or Unknown (no observed
// address, Run not finished, the self-test already ran or is running, every
// send failed, or ctx ended), and records True and False in the table.
//
// The self-test runs at most once per prober: its two packets are part of
// the family's probe-class bound of 31, which the
// prober enforces itself. A ctx that already ended sends nothing.
//
// The runtime calls it only when probe_summary.pair.same_public_ip[family]
// holds; it does not block ready or go. The source address of the returning
// packet is not checked: the NAT rewrites it.
func (p *Prober) Hairpin(ctx context.Context) protocol.Tri {
	if p == nil || !p.finished.Load() || !p.hairpin.CompareAndSwap(false, true) {
		return protocol.TriUnknown
	}
	if ctx == nil {
		ctx = context.Background()
	}
	res := protocol.TriUnknown
	if err := life.Safe("probe/hairpin/"+string(p.spec.Family), func() { res = p.runHairpin(ctx) }); err != nil {
		return protocol.TriUnknown
	}
	return res
}

func (p *Prober) runHairpin(ctx context.Context) protocol.Tri {
	target := p.observed
	if !target.IsValid() {
		return protocol.TriUnknown
	}
	for drained := false; !drained; {
		select {
		case <-p.inbox: // late replies of the probing phase
		default:
			drained = true
		}
	}
	p.active.Store(true)
	defer p.active.Store(false)
	var pending []uint32
	buf := make([]byte, 0, udpwire.PeerOuterSize+udpwire.MaxPlaintext+udpwire.TagSize)
	send := func() {
		h := udpwire.Header{Type: udpwire.THairpin, Role: p.role, Sock: p.primaryID, Cand: udpwire.NoCand,
			Seq: p.spec.Codec.NextSeq(), TS: p.spec.Codec.Now()}
		pkt, err := p.spec.Codec.Seal(buf[:0], &h, nil, 0)
		if err == nil {
			err = writeProbe(p.primary, pkt, target)
		}
		if err == nil {
			pending = append(pending, h.Seq)
		}
	}
	if ctx.Err() != nil {
		return protocol.TriUnknown
	}
	t0 := p.clk.Now()
	send()
	timer := p.clk.NewTimer(hairpinGap)
	defer timer.Stop()
	second := false
	for {
		select {
		case <-ctx.Done():
			return protocol.TriUnknown
		case in := <-p.inbox:
			if !in.stun && in.h.Type == udpwire.THairpin && in.sock == p.primaryID && in.h.Sock == p.primaryID &&
				slices.Contains(pending, in.h.Seq) {
				p.table.SetHairpin(protocol.TriTrue)
				return protocol.TriTrue
			}
		case <-timer.C():
			if ctx.Err() != nil {
				return protocol.TriUnknown
			}
			if !second {
				second = true
				send()
				timer.Reset(hairpinWindow - p.clk.Now().Sub(t0))
				continue
			}
			if len(pending) == 0 {
				return protocol.TriUnknown
			}
			p.table.SetHairpin(protocol.TriFalse)
			return protocol.TriFalse
		}
	}
}
