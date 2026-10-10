// Package natprobe may hold netimpl functions.
package natprobe

import "net"

// Listen is natprobe's default listener.
//
//holepunch:netimpl
func Listen(addr *net.UDPAddr) (*net.UDPConn, error) {
	return net.ListenUDP("udp", addr)
}
