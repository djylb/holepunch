// Command holepunch forwards TCP over a punched UDP path: a host exposes
// TCP targets under an ID, a dialer connects to the host by ID and forwards
// a local listener to one of them, over QUIC (package quicforward).
//
// Usage:
//
//	holepunch host    -server ADDR -pin PIN -id ID -target HOST:PORT [-target ...]
//	holepunch connect -server ADDR -pin PIN -id ID -listen 127.0.0.1:PORT [-target HOST:PORT]
//
// Both take -auth-token, -ca (instead of -pin), -server-name, -local-ip,
// -local-interface, -portmap and -debug. The host's first -target is the
// default for dialers that name none; a dialer may only reach the targets
// the host lists (and that the server's policy allows). The host registers
// again by itself when its link to the server is lost; the dialer opens a
// new session when its QUIC connection is lost. SIGINT or SIGTERM stops
// either.
package main
