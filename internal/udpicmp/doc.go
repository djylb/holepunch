// Package udpicmp handles the ICMP error reports that operating systems
// deliver on UDP sockets.
//
// Hole punching sends to closed ports and with low TTLs all the time, so
// "port unreachable" and "time exceeded" come back all the time. Linux and
// the BSDs report them only on connected sockets; Windows reports them on an
// unconnected socket too, as WSAECONNRESET or WSAENETRESET on the next read
// or write. Such a report is a soft signal about an earlier datagram, never
// a sign that the socket stopped working.
//
// DisableReports switches the Windows reports off on a socket; it is a no-op
// elsewhere. IsReport and IsNoRoute classify an error by its errno on every
// platform, so a socket whose reports stay on — an injected conn, say — is
// handled the same way.
//
// The package is stateless: no goroutines, no package state, no ownership
// of the conns it is given. It depends on the standard library only.
package udpicmp
