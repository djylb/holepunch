# quicpath

`github.com/djylb/holepunch/quicpath` runs QUIC ([quic-go](https://github.com/quic-go/quic-go))
on the UDP sockets a `holepunch.Session` hands over: one QUIC connection — a
pipe — per confirmed path, mutually authenticated with certificate pins that
travel through the coordinator.

It is a separate module so that the holepunch module does not depend on
quic-go.

```sh
go get github.com/djylb/holepunch/quicpath
```

## Usage

```go
id, err := quicpath.NewIdentity("my-app") // one identity serves any number of sessions

sess, err := holepunch.Punch(ctx, ctl, holepunch.Options{
	TransportMode: "quic",
	TransportData: id.TransportData(), // announces the certificate pin to the peer
})
if err != nil { /* relay */ }

conf, err := id.TLSConfig(sess.Result()) // pins the certificate the peer announced
var conn *quicpath.Conn
if sess.Result().Role == protocol.RoleInitiator {
	conn, err = quicpath.Dial(ctx, sess, conf, nil)
} else {
	conn, err = quicpath.Accept(ctx, sess, conf, nil)
}
if err != nil {
	_ = sess.Close()
	return err
}
defer conn.Close() // the QUIC connection, its transport, then the session

st, err := conn.QUIC().OpenStreamSync(ctx)
```

- `Dial` (initiator) and `Accept` (responder) run on the primary path and wait
  at most the session's `TransportTimeout`. The responder takes connections from
  the path's confirmed peer address only. On success the `Conn` owns the
  session; on error the session stays the caller's.
- `Identity` is a self-signed certificate; `TLSConfig` checks the peer's
  certificate against the pin in `Result.PeerTransportData` on every handshake
  and never resumes a TLS session. Any other `tls.Config` works too, as long as
  it names an application protocol (`NextProtos`).
- The QUIC keep-alive period and idle timeout default to the path's keepalive
  advice; a `quic.Config` passed in overrides them field by field.
- The raw socket needs no residual filter: holepunch's late handshake packets
  are dropped by QUIC as non-QUIC datagrams.

## Liveness

`Conn.Done()` is closed when the pipe dies and `Conn.Err()` says why:
`ErrIdleTimeout` (the path went silent), `ErrPeerClosed` (the peer closed or
reset the connection), `ErrClosed` (closed on this side) — each wrapping
quic-go's own error — or quic-go's error as is. An upper layer watches `Done`
and replaces or drops the pipe.

## Several paths

With `holepunch.Options.MaxPaths` above 1 a session holds extra paths, possibly
sharing a socket with the primary one. An `Endpoint` owns the session and one
QUIC transport per socket, and runs a pipe on any path:

```go
ep, err := quicpath.NewEndpoint(sess, conf, nil)
defer ep.Close() // every pipe, the transports, the session

for i := range ep.Paths() {
	pipe, err := ep.Dial(ctx, i) // the responder calls ep.Accept(ctx, i)
	// ...
}
```

A path whose pipe died can carry a new one: dial and accept it again.
