// Command gen is a tool, not library: never reported.
package main

import (
	"net"
	"time"
)

var calls int

func main() {
	calls++
	go main()
	time.Sleep(1)
	_, _ = net.Dial("udp", "x:1")
}
