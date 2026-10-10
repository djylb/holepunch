package natprobe

import (
	"encoding/binary"
	"net/netip"
	"sync"
)

// srcShards is the number of source limiter shards.
const srcShards = 16

// sourceLimiter is the per-source-prefix token bucket (v4 /32, v6 /64) that
// runs before the route lookup, so a flood of
// random routes costs a hash and a map lookup each. It is a bounded, sharded
// LRU of GCRA states with preallocated nodes: a known prefix costs no
// allocation and an unknown one evicts the least recently used.
type sourceLimiter struct {
	rate   Rate
	shards [srcShards]srcShard
}

// srcKey is a source prefix: an IPv4 address, or the upper 64 bits of an
// IPv6 address.
type srcKey struct {
	v6 bool
	p  uint64
}

type srcNode struct {
	key        srcKey
	tat        int64
	prev, next int32
}

type srcShard struct {
	mu         sync.Mutex
	idx        map[srcKey]int32
	nodes      []srcNode
	head, tail int32 // most and least recently used; -1 when empty
	_          [40]byte
}

// newSourceLimiter returns a limiter for rate holding about size prefixes, or
// nil when rate.PerSec < 0 (disabled).
func newSourceLimiter(rate Rate, size int) *sourceLimiter {
	if rate.PerSec < 0 {
		return nil
	}
	per := max(size/srcShards, 1)
	l := &sourceLimiter{rate: rate}
	for i := range l.shards {
		sh := &l.shards[i]
		sh.idx = make(map[srcKey]int32, per)
		sh.nodes = make([]srcNode, 0, per)
		sh.head, sh.tail = -1, -1
	}
	return l
}

func prefixKey(a netip.Addr) srcKey {
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		return srcKey{p: uint64(binary.BigEndian.Uint32(b[:]))}
	}
	b := a.As16()
	return srcKey{v6: true, p: binary.BigEndian.Uint64(b[:8])}
}

// allow admits one packet from a at monotonic time now (ns).
func (l *sourceLimiter) allow(a netip.Addr, now int64) bool {
	if l == nil {
		return true
	}
	k := prefixKey(a)
	h := k.p * 0x9E3779B97F4A7C15 // Fibonacci hashing spreads adjacent prefixes over the shards
	if k.v6 {
		h ^= 0xA5A5A5A5A5A5A5A5
	}
	sh := &l.shards[h>>60]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	i, ok := sh.idx[k]
	if ok {
		sh.touch(i)
	} else {
		i = sh.insert(k)
	}
	return gcra(&sh.nodes[i].tat, now, l.rate)
}

// insert adds k as the most recent node, evicting the least recent one when
// the shard is full.
func (sh *srcShard) insert(k srcKey) int32 {
	var i int32
	if len(sh.nodes) < cap(sh.nodes) {
		sh.nodes = append(sh.nodes, srcNode{})
		i = int32(len(sh.nodes) - 1)
	} else {
		i = sh.tail
		delete(sh.idx, sh.nodes[i].key)
		sh.unlink(i)
	}
	sh.nodes[i] = srcNode{key: k, prev: -1, next: -1}
	sh.idx[k] = i
	sh.pushFront(i)
	return i
}

func (sh *srcShard) touch(i int32) {
	if sh.head == i {
		return
	}
	sh.unlink(i)
	sh.pushFront(i)
}

func (sh *srcShard) unlink(i int32) {
	n := &sh.nodes[i]
	if n.prev >= 0 {
		sh.nodes[n.prev].next = n.next
	} else {
		sh.head = n.next
	}
	if n.next >= 0 {
		sh.nodes[n.next].prev = n.prev
	} else {
		sh.tail = n.prev
	}
	n.prev, n.next = -1, -1
}

func (sh *srcShard) pushFront(i int32) {
	n := &sh.nodes[i]
	n.prev, n.next = -1, sh.head
	if sh.head >= 0 {
		sh.nodes[sh.head].prev = i
	}
	sh.head = i
	if sh.tail < 0 {
		sh.tail = i
	}
}
