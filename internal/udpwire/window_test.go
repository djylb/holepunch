package udpwire

import "testing"

// TestSeqWindow checks duplicates, too old, window crossing, reordering at
// exactly 1023 (accepted) and 1024 (rejected), seq 0 and jumps.
func TestSeqWindow(t *testing.T) {
	type step struct {
		seq  uint32
		want bool
	}
	cases := []struct {
		name  string
		steps []step
	}{
		{"zero", []step{{0, false}, {1, true}, {0, false}}},
		{"duplicate", []step{{1, true}, {1, false}, {2, true}, {1, false}, {2, false}}},
		{"in-order run", []step{{1, true}, {2, true}, {3, true}, {4, true}}},
		{"reorder within window", []step{{10, true}, {5, true}, {9, true}, {5, false}, {1, true}}},
		{"edge 1023 accepted", []step{{2000, true}, {2000 - 1023, true}, {2000 - 1023, false}}},
		{"edge 1024 rejected", []step{{2000, true}, {2000 - 1024, false}}},
		{"slide drops old", []step{{1, true}, {1025, true}, {1, false}, {2, true}, {2, false}}},
		{"jump beyond window clears", []step{{5, true}, {100000, true}, {5, false}, {100000 - 1023, true}, {100000, false}}},
		{"word boundaries", []step{{63, true}, {64, true}, {65, true}, {127, true}, {128, true}, {64, false}, {63, false}}},
		{"partial-word slide", []step{{1000, true}, {1060, true}, {1000, false}, {1001, true}, {1059, true}, {1059, false}}},
		{"near uint32 max", []step{{^uint32(0) - 1, true}, {^uint32(0), true}, {^uint32(0), false}, {^uint32(0) - 1, false}, {^uint32(0) - 1023, true}}},
	}
	for _, c := range cases {
		var w SeqWindow
		for i, s := range c.steps {
			if got := w.Accept(s.seq); got != s.want {
				t.Errorf("%s step %d: Accept(%d) = %v, want %v", c.name, i, s.seq, got, s.want)
			}
		}
	}
}

// TestSeqWindowModel compares SeqWindow with a map-based model over random
// sequences mixing in-order traffic, reordering, duplicates and jumps.
func TestSeqWindowModel(t *testing.T) {
	r := newRand(6)
	for range iterations(200) {
		var w SeqWindow
		seen := map[uint32]bool{}
		var top uint32
		next := uint32(1)
		for range 3000 {
			var seq uint32
			switch x := r.IntN(10); {
			case x < 5:
				seq = next
				next++
			case x < 8 && top > 0:
				seq = top - uint32(r.IntN(int(min(top, 1500))))
			case x < 9:
				next += uint32(r.IntN(3000))
				seq = next
			default:
				seq = uint32(r.IntN(int(next) + 1))
			}
			want := seq != 0 && !seen[seq] && (seq > top || top-seq < windowSize)
			if got := w.Accept(seq); got != want {
				t.Fatalf("Accept(%d) with top %d = %v, want %v", seq, top, got, want)
			}
			if want {
				seen[seq] = true
				top = max(top, seq)
			}
		}
	}
}
