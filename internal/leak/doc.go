// Package leak provides the resource accounting that package goroutines
// does not cover: sockets opened through a holepunch Network and file
// descriptors of the process.
//
// TrackingNetwork wraps any implementation of the Network method set — the
// same set as holepunch.Network, declared here with std types only so that
// this package does not import the root package — and counts, per purpose,
// every socket returned by ListenPacket, its first Close, and every failed
// or nil result. A test asserts with CheckOpen that exactly the sockets
// handed to the caller are still open after a session (1 on success, 0 on
// failure) and with CheckClosed that nothing is open once the caller has
// closed its session; a failure lists the open sockets in opening order.
//
// The connections returned by TrackingNetwork are made by Wrap, which tests
// also use to intercept a socket's reads, writes, hop limit and Close
// (Hooks). They have the address-port calls ReadFromUDPAddrPort and
// WriteToUDPAddrPort and exactly the optional capabilities of the wrapped
// connection that the library probes for — HopLimiter, syscall.Conn,
// SetReadBuffer and SetWriteBuffer — and no others, so wrapping never changes
// which code path the library takes.
//
// OpenFDs counts the descriptors of the process on darwin (/dev/fd) and linux
// (/proc/self/fd); CheckFDs waits until the count is back at a baseline.
//
// # Concurrency and ownership
//
// A TrackingNetwork is safe for concurrent use. It owns nothing: closing a
// tracked connection closes the wrapped one, and the wrapped Network stays
// owned by the test. No goroutines are started.
package leak
