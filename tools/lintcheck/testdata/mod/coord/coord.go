// Package coord exercises facts that cross package boundaries.
package coord

import (
	"fmt"
	"net"
	"sync"

	"example.com/mod/internal/conf"
	"example.com/mod/internal/life"
)

type relay struct {
	mu   sync.Mutex
	opts struct{ OnProgress func(string) }
}

func (r *relay) notify() {}

func (r *relay) forward() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.opts.OnProgress("x")              // want "callbacklock"
	r.notify()                          // unexported callback names of package mod do not apply here
	_ = life.Safe("forward", func() {}) // want "callbacklock"
	return fmt.Errorf("plain call")
}

func tune() { conf.Limit = 5 }

// dialOut is not in a package that may implement the network.
//
//holepunch:netimpl // want "directive"
func dialOut() {
	c, _ := net.Dial("udp", "x:1") // want "nodirectnet"
	_ = c
}
