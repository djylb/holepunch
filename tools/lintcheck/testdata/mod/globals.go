package mod

import (
	"errors"
	"sync"
	"sync/atomic"
)

var ErrClosed = errors.New("closed")
var errTimeout = &timeoutError{}
var phases = map[string]int{"a": 1}
var table = [3]int{1, 2, 3}
var initOnly = map[string]bool{}
var bufPool = sync.Pool{New: func() any { return new([64]byte) }}
var ptrPool = &sync.Pool{}
var _ = phases

var counter int                 // want "noglobalstate"
var registry = map[string]int{} // want "noglobalstate"
var mu sync.Mutex               // want "noglobalstate"
var once = &sync.Once{}         // want "noglobalstate"
var hits atomic.Int64           // want "noglobalstate"
var events = make(chan int, 1)  // want "noglobalstate"
var defaults = &Options{}       // want "noglobalstate"
var boxed = new(int)            // want "noglobalstate"
var aliased = &table            // want "noglobalstate"
var escaped int                 // want "noglobalstate"
var appended []int              // want "noglobalstate"
var swapped = 1                 // want "noglobalstate"
var removed = map[int]bool{}    // want "noglobalstate"
var ranged int                  // want "noglobalstate"
var hook = func() {}            // want "noglobalstate"
var Exported = 1                // want "noglobalstate"

type timeoutError struct{}

func (*timeoutError) Error() string { return "timeout" }

func init() { initOnly["x"] = true }

func bump() { counter++ }

func register(k string) { registry[k] = phases[k] }

func shadow() {
	table := []int{0}
	table[0] = 1
}

func paramShadow(counter int) int {
	counter++
	return counter
}

func readAll() int {
	return table[0] + len(initOnly) + int(hits.Load()) + *boxed + len(events) + aliased[0]
}

func escape() *int { return &escaped }

func grow() []int { return append(appended, 1) }

func swap() { swapped, _ = 2, 3 }

func drop() { delete(removed, 1) }

func rangeInto(xs []int) {
	for _, ranged = range xs {
	}
}

func usePools() {
	b := bufPool.Get()
	bufPool.Put(b)
	ptrPool.Put(b)
	mu.Lock()
	mu.Unlock()
	once.Do(func() {})
	_, _ = defaults, errTimeout
	hook()
}
