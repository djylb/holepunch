//go:build holepunch_faultinject

package mod

import "time"

// Only in the fault-injection test build: not checked.
var armed = map[string]int{}

func taggedOnly() {
	armed["x"]++
	go taggedOnly()
	time.Sleep(1)
}
