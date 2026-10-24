// Package standalone is the root of holepunch's reference deployment: a
// complete server and client built on the holepunch library alone.
//
// # Layout
//
//   - proto: the standalone signalling messages (register, open, join, the
//     session description, heartbeats) that precede holepunch's own control
//     protocol on the same TLS stream, and the AccessPolicy a session carries.
//   - broker: the host registry and the matchmaking of dialers with hosts;
//     it composes a coord.Coordinator, which runs every session.
//   - server: the TLS front end that authenticates clients, keeps the host
//     registration links and hands each session's stream to the broker.
//   - client: the client side — opening sessions as a dialer, serving
//     incoming sessions as a registered host — on top of
//     holepunch.Punch.
//   - quicforward: TCP forwarding over QUIC (quic-go, run on the punched UDP
//     path by the quicpath module), with both QUIC certificates pinned
//     through the coordinator.
//   - cmd/holepunchd, cmd/holepunch, cmd/holepunch-diag: the server, the
//     forwarding client and the diagnostic client.
//
// This package itself only holds the operating-system network access the
// other packages use by default (DialTCP, ListenTCP). Every package takes an
// injected dialer or listener instead, so that the tests run the whole
// deployment inside a nattest network.
//
// # Dependencies
//
// The client side (client, quicforward, cmd/holepunch, cmd/holepunch-diag)
// never links the server side (broker, server, coord, natprobe); proto is
// shared by both and depends on the standard library and internal/life
// only. The module imports only public packages of the library and of
// quicpath:
// internal/life is the module's own goroutine, recover and read-interrupt
// boundary.
package standalone
