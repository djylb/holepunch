package nattest

import (
	"net/netip"
	"time"
)

// portBitmap marks the external ports of one address held by mappings.
type portBitmap [1024]uint64

func (b *portBitmap) get(p uint16) bool { return b[p>>6]&(1<<(p&63)) != 0 }
func (b *portBitmap) set(p uint16)      { b[p>>6] |= 1 << (p & 63) }
func (b *portBitmap) clear(p uint16)    { b[p>>6] &^= 1 << (p & 63) }

func (f *natFam) bitmap(ip netip.Addr) *portBitmap {
	b := f.used[ip]
	if b == nil {
		b = new(portBitmap)
		f.used[ip] = b
	}
	return b
}

// free reports whether ext:port is held neither by a mapping nor by port
// noise at network time now. Port 0 never comes up: ranges and pools start at
// 1 (NATConfig.normalized).
func (f *natFam) free(ext netip.Addr, port uint16, now time.Duration) bool {
	if b := f.used[ext]; b != nil && b.get(port) {
		return false
	}
	return !f.noise.holds(netip.AddrPortFrom(ext, port), now)
}

// wrap folds x into [lo, hi].
func (f *natFam) wrap(x int) int {
	n := f.hi - f.lo + 1
	return f.lo + ((x-f.lo)%n+n)%n
}

// allocPort picks an external port on ext by strategy alloc for a mapping
// of an internal endpoint with port want; nat.mu is held.
func (nat *NAT) allocPort(f *natFam, alloc PortAlloc, ext netip.Addr, want uint16, now time.Duration) (uint16, bool) {
	inRange := int(want) >= f.lo && int(want) <= f.hi
	switch alloc.kind() {
	case Preserve:
		if inRange && f.free(ext, want, now) {
			return want, true
		}
		return nat.seqNext(f, ext, now)
	case PreserveThenSequential:
		if inRange && f.free(ext, want, now) {
			return want, true
		}
		return nat.walk(f, ext, f.wrap(int(want)), now)
	case PreserveThenRandom:
		if inRange && f.free(ext, want, now) {
			return want, true
		}
		return nat.randomFree(f, ext, f.lo, f.hi, now)
	case Sequential:
		return nat.seqNext(f, ext, now)
	case allocPool:
		lo, hi := alloc.bounds()
		return nat.randomFree(f, ext, int(lo), int(hi), now)
	default: // Random, and any unknown strategy
		return nat.randomFree(f, ext, f.lo, f.hi, now)
	}
}

// seqNext advances the Sequential cursor of ext. The cursor starts at a
// seeded random port, as on real devices, so that tests cannot rely on a
// fixed first port.
func (nat *NAT) seqNext(f *natFam, ext netip.Addr, now time.Duration) (uint16, bool) {
	c, ok := f.cursor[ext]
	if !ok {
		c = f.lo + nat.rng.IntN(f.hi-f.lo+1)
	}
	p, ok := nat.walk(f, ext, c, now)
	if ok {
		f.cursor[ext] = int(p)
	}
	return p, ok
}

// walk returns the first free port after start in steps of PortStep. When the
// step's orbit is exhausted (a step that shares a factor with the range size
// visits only part of it), it falls back to single steps so that a free port
// is found whenever one exists.
func (nat *NAT) walk(f *natFam, ext netip.Addr, start int, now time.Duration) (uint16, bool) {
	size := f.hi - f.lo + 1
	c := start
	for range size {
		c = f.wrap(c + f.step)
		if f.free(ext, uint16(c), now) {
			return uint16(c), true
		}
	}
	for range size {
		c = f.wrap(c + 1)
		if f.free(ext, uint16(c), now) {
			return uint16(c), true
		}
	}
	return 0, false
}

// randomFree draws free ports uniformly from [lo, hi]. After a bounded number
// of misses it scans from a random offset, which keeps a nearly full range
// fast and still finds the last free port.
func (nat *NAT) randomFree(f *natFam, ext netip.Addr, lo, hi int, now time.Duration) (uint16, bool) {
	size := hi - lo + 1
	for range 64 {
		c := lo + nat.rng.IntN(size)
		if f.free(ext, uint16(c), now) {
			return uint16(c), true
		}
	}
	start := nat.rng.IntN(size)
	for i := range size {
		c := lo + (start+i)%size
		if f.free(ext, uint16(c), now) {
			return uint16(c), true
		}
	}
	return 0, false
}

// portNoise is the port consumption of the other subscribers of a NAT
// (NATConfig.PortNoisePPS): a Poisson process realized lazily, whenever the NAT
// allocates a port or is observed, instead of by a background goroutine. The
// result is the same as a real-time process, but deterministic under a fake
// clock and free of goroutines.
type portNoise struct {
	next  time.Duration                    // arrival time of the next event
	held  map[netip.AddrPort]time.Duration // port -> held until
	queue []noiseHold                      // the holds in order of expiry
	head  int
}

type noiseHold struct {
	ep    netip.AddrPort
	until time.Duration
}

// maxNoiseCatchUp bounds the events realized by one catch-up, so that a fake
// clock advanced by hours does not stall the test; the process restarts from
// the present after the bound.
const maxNoiseCatchUp = 1 << 16

func (pn *portNoise) holds(ep netip.AddrPort, now time.Duration) bool {
	if len(pn.held) == 0 {
		return false
	}
	t, ok := pn.held[ep]
	return ok && t > now
}

func (pn *portNoise) add(ep netip.AddrPort, until time.Duration) {
	if pn.held == nil {
		pn.held = make(map[netip.AddrPort]time.Duration)
	}
	pn.held[ep] = until
	pn.queue = append(pn.queue, noiseHold{ep, until})
}

// expire releases the holds that ended at or before now.
func (pn *portNoise) expire(now time.Duration) {
	for pn.head < len(pn.queue) && pn.queue[pn.head].until <= now {
		e := pn.queue[pn.head]
		if t, ok := pn.held[e.ep]; ok && t == e.until {
			delete(pn.held, e.ep)
		}
		pn.queue[pn.head] = noiseHold{}
		pn.head++
	}
	if pn.head > 256 && pn.head*2 > len(pn.queue) {
		k := copy(pn.queue, pn.queue[pn.head:])
		pn.queue = pn.queue[:k]
		pn.head = 0
	}
}

func (pn *portNoise) active() int { return len(pn.held) }

func (pn *portNoise) reset() {
	clear(pn.held)
	pn.queue, pn.head = nil, 0
}

// realizeNoise brings the port noise of f up to now; nat.mu is held. Each
// event allocates a port with the NAT's own strategy, so that it moves the
// Sequential cursor exactly like another subscriber's new mapping, and holds
// it for MappingTimeout.
func (nat *NAT) realizeNoise(f *natFam, now time.Duration) {
	if nat.cfg.PortNoisePPS <= 0 || f.mode != modeTranslate || nat.inert {
		return
	}
	hold := nat.timeout
	if hold < 0 {
		hold = defaultMappingTimeout
	}
	for i := 0; f.noise.next <= now; i++ {
		if i == maxNoiseCatchUp {
			f.noise.next = now + nat.noiseGap()
			break
		}
		t := f.noise.next
		f.noise.expire(t)
		ext := f.ext[nat.rng.IntN(len(f.ext))]
		want := uint16(defaultPortLo + nat.rng.IntN(defaultPortHi-defaultPortLo+1))
		if port, ok := nat.allocPort(f, f.alloc, ext, want, t); ok {
			f.noise.add(netip.AddrPortFrom(ext, port), t+hold)
			nat.cnt.noiseAllocs++
		}
		f.noise.next += nat.noiseGap()
	}
	f.noise.expire(now)
}

// noiseGap draws the exponential gap between two noise events.
func (nat *NAT) noiseGap() time.Duration {
	return time.Duration(nat.rng.ExpFloat64() / nat.cfg.PortNoisePPS * float64(time.Second))
}
