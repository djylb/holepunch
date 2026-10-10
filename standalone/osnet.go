package standalone

import (
	"context"
	"net"
)

// DialTCP opens a TCP connection to address ("host:port") with the operating
// system's network. The standalone packages use it when the caller injects
// no dialer of its own.
//
//holepunch:netimpl
func DialTCP(ctx context.Context, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", address)
}

// ListenTCP opens a TCP listener on address ("host:port", ":port") with the
// operating system's network.
//
//holepunch:netimpl
func ListenTCP(address string) (net.Listener, error) {
	return net.Listen("tcp", address)
}
