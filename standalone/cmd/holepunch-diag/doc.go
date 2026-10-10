// Command holepunch-diag diagnoses direct connectivity through a holepunchd
// server: one side registers as an echo host, the other punches a session to
// it and measures the punched UDP path.
//
// Usage:
//
//	holepunch-diag echo  -server ADDR -pin PIN -id ID
//	holepunch-diag probe -server ADDR -pin PIN -id ID [-count 5] [-interval 500ms]
//
// Both print, for every session, how the punch went: the NAT traits the
// server measured for each side and family, the winning strategy and round,
// the time spent in each phase and the keepalive advice. probe then sends
// -count datagrams over the path and prints each round-trip time; echo
// returns every datagram from the punched peer until the path has been idle
// for 30 s. The datagrams go through the residual filter of a non-QUIC upper
// layer (client.Session.PacketConn). Both take the client flags of holepunch
// (-auth-token, -ca, -server-name, -local-ip, -local-interface, -portmap,
// -debug).
package main
