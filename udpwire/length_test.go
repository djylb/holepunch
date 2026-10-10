package udpwire

import "testing"

// TestNewPadPolicy checks that 10⁴ coordinator draws stay inside
// payload_min ∈ [48, 160], span ∈ [64, 256], max ≤ 1024, cover the ranges,
// and two sessions share an interval about as rarely as chance predicts.
func TestNewPadPolicy(t *testing.T) {
	r := newRand(3)
	const n = 10000
	mins, spans := map[int]bool{}, map[int]bool{}
	seen := map[PadPolicy]int{}
	for range n {
		p := NewPadPolicy(r)
		lo, span := int(p.Min), int(p.Max)-int(p.Min)
		if lo < padMinLow || lo > padMinHigh || span < padSpanLow || span > padSpanHigh || p.Max > MaxPlaintext {
			t.Fatalf("policy %+v out of range", p)
		}
		if q, err := p.clamp(); err != nil || q != p {
			t.Fatalf("policy %+v is changed by the client clamp", p)
		}
		mins[lo], spans[span] = true, true
		seen[p]++
	}
	if len(mins) != padMinHigh-padMinLow+1 || len(spans) != padSpanHigh-padSpanLow+1 {
		t.Errorf("coverage: %d mins, %d spans", len(mins), len(spans))
	}
	// 113 × 193 equiprobable intervals: two random sessions collide with
	// probability ≈ 1/21809. Allow three times that.
	pairs, same := float64(n)*float64(n-1)/2, 0.0
	for _, k := range seen {
		same += float64(k) * float64(k-1) / 2
	}
	if rate := same / pairs; rate > 3.0/21809 {
		t.Errorf("collision rate %.6f", rate)
	}
	if p := NewPadPolicy(nil); p.Min < padMinLow || p.Max > MaxPlaintext {
		t.Errorf("nil rand: %+v", p)
	}
}

// TestReplyLengths checks the reply length rules: no reply below 83 bytes,
// never more reply bytes than request bytes — counting the opener of a wrapped
// probe's replies — each reply within the envelope S maximum, minimum legal
// lengths respected, and ≥ 90 % of the possible lengths used.
func TestReplyLengths(t *testing.T) {
	r := newRand(5)
	for _, req := range []int{0, minAckWire - 1, maxProbePacket + 1, 1 << 20} {
		for _, second := range []bool{false, true} {
			if a, b := ReplyLengths(req, second, false, r); a != 0 || b != 0 {
				t.Errorf("ReplyLengths(%d, %v) = %d, %d; want no reply", req, second, a, b)
			}
		}
	}
	for _, req := range []int{0, minAckWire + maxWrapOverhead - 1, MaxWrapped + 1} {
		if a, b := ReplyLengths(req, true, true, r); a != 0 || b != 0 {
			t.Errorf("wrapped ReplyLengths(%d) = %d, %d; want no reply", req, a, b)
		}
	}
	for _, wrapped := range []bool{false, true} {
		cost := func(plain int) int { return plain + replyOverhead }
		hi := maxProbePacket
		if wrapped {
			cost = func(plain int) int { n := plain + replyOverhead; return n + wrapOverhead + (4-n%4)%4 }
			hi = MaxWrapped
		}
		for req := minAckWire; req <= hi; req++ {
			for _, second := range []bool{false, true} {
				for range 20 {
					ack, sec := ReplyLengths(req, second, wrapped, r)
					if ack == 0 {
						if !wrapped || req >= minAckWire+maxWrapOverhead {
							t.Fatalf("req %d wrapped %v: no reply", req, wrapped)
						}
						continue
					}
					if ack < MinAckPlaintext || ack+replyOverhead > maxPeerPacket {
						t.Fatalf("req %d: ack plaintext %d", req, ack)
					}
					total := cost(ack)
					switch {
					case sec > 0:
						if !second || sec < MinExtraPlaintext || sec+replyOverhead > maxPeerPacket {
							t.Fatalf("req %d: second plaintext %d", req, sec)
						}
						total += cost(sec)
					case second && !wrapped && req >= minPairWire:
						t.Fatalf("req %d: no second reply", req)
					}
					if total > req {
						t.Fatalf("req %d wrapped %v: replies total %d bytes", req, wrapped, total)
					}
				}
			}
		}
	}
	// Coverage: the ack alone spans [83, L]; with a second reply the total
	// spans [156, L].
	for _, req := range []int{minPairWire, 189, 269, maxPeerPacket, maxProbePacket} {
		acks, totals := map[int]bool{}, map[int]bool{}
		for range 200 * req {
			a, _ := ReplyLengths(req, false, false, r)
			acks[a+replyOverhead] = true
			a, b := ReplyLengths(req, true, false, r)
			totals[a+b+2*replyOverhead] = true
		}
		if want := min(req, maxPeerPacket) - minAckWire + 1; len(acks) < want*9/10 {
			t.Errorf("req %d: %d of %d ack lengths", req, len(acks), want)
		}
		if want := req - minPairWire + 1; len(totals) < want*9/10 {
			t.Errorf("req %d: %d of %d two-reply totals", req, len(totals), want)
		}
	}
	if a, _ := ReplyLengths(200, false, false, nil); a < MinAckPlaintext {
		t.Errorf("nil rand: %d", a)
	}
	// Replies at the computed lengths always seal.
	srv := newCodec(t, RoleServer)
	for _, req := range []int{minAckWire, minPairWire, maxProbePacket} {
		ack, sec := ReplyLengths(req, true, false, r)
		h, tl := headerFor(srv, TProbeAck), tlvsFor(TProbeAck)
		if _, err := srv.Seal(nil, &h, &tl, ack); err != nil {
			t.Errorf("req %d: ack: %v", req, err)
		}
		if sec > 0 {
			h, tl := headerFor(srv, TProbeExtra), tlvsFor(TProbeExtra)
			if _, err := srv.Seal(nil, &h, &tl, sec); err != nil {
				t.Errorf("req %d: extra: %v", req, err)
			}
		}
	}
}
