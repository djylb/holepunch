// Package udpsock holds the socket-level helpers that UDP NAT traversal
// needs and package net leaves out: ICMP error reports, the unicast TTL,
// and truncated reads.
//
// # ICMP error reports
//
// Hole punching sends to closed ports and with low TTLs all the time, so
// "port unreachable" and "time exceeded" come back all the time. Linux and
// the BSDs report them only on connected sockets; Windows reports them on an
// unconnected socket too, as WSAECONNRESET or WSAENETRESET on the next read
// or write. Such a report is a soft signal about an earlier datagram, never
// a sign that the socket stopped working.
//
// DisableICMPReports switches the Windows reports off on a socket; it is a
// no-op elsewhere. IsICMPReport and IsNoRoute classify an error by its
// errno on every platform, so a socket whose reports stay on — one a
// library created, say — is handled the same way: a read loop goes on
// reading after an IsICMPReport error.
//
// # TTL
//
// HopLimit and SetHopLimit read and set the unicast TTL (IPv4) or hop limit
// (IPv6) of a socket, on Unix and Windows: a datagram sent with a low TTL
// opens a mapping in the local NATs and expires before it reaches the peer's.
//
// # Truncated reads
//
// IsTruncated recognises the read error of a datagram larger than the
// buffer, which only Windows reports; other systems truncate silently.
//
// The package is stateless: no goroutines, no package state, no ownership
// of the conns it is given. It depends on the standard library only.
package udpsock
