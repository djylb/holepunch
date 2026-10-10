package udpwire

// Replay window geometry: 1024 sequence numbers in a ring of 16 words.
const (
	windowSize  = 1024
	wordBits    = 64
	windowWords = windowSize / wordBits
)

// SeqWindow is a 1024-entry sliding replay window over Header.Seq,
// one per (receiver, sender role). It depends on no clock, so clock skew
// cannot make a session fail. The zero value is ready to use; it is not safe
// for concurrent use.
type SeqWindow struct {
	top  uint32
	bits [windowWords]uint64 // bit seq%1024 is set once seq has been accepted
}

// Accept reports whether seq is new and records it. It must run after the
// AEAD has authenticated the packet, since seq is only trustworthy then.
// Rejected: seq 0, a seq already accepted, and a seq 1024 or more below the
// highest accepted. A seq above the highest slides the window forward.
func (w *SeqWindow) Accept(seq uint32) bool {
	if seq == 0 {
		return false
	}
	if seq > w.top {
		w.advance(seq)
	} else if w.top-seq >= windowSize {
		return false
	}
	word, bit := &w.bits[seq/wordBits%windowWords], uint64(1)<<(seq%wordBits)
	if *word&bit != 0 {
		return false
	}
	*word |= bit
	return true
}

// advance moves top to seq, clearing the ring positions of top+1 … seq, which
// until now held sequence numbers that have just left the window. Clearing
// exact bit runs (not whole words) keeps the window at exactly 1024 entries.
func (w *SeqWindow) advance(seq uint32) {
	gap := seq - w.top
	w.top = seq
	if gap >= windowSize {
		w.bits = [windowWords]uint64{}
		return
	}
	for s := seq - gap + 1; gap > 0; {
		bit := s % wordBits
		run := min(wordBits-bit, gap)
		w.bits[s/wordBits%windowWords] &^= ^uint64(0) >> (wordBits - run) << bit
		s += run
		gap -= run
	}
}
