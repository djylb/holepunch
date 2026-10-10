# holepunch

UDP hole punching for Go. Two clients that both reach a coordinator server
get a direct UDP path to each other, and the library hands the confirmed
socket to the caller.

The caller provides an authenticated control connection to the coordinator
and decides what to do when no direct path exists (for example, keep using a
relay). Everything between those two points is the library's job: NAT
measurement, planning, synchronized punching, path confirmation and handover.

Requires Go 1.26.

## Install

```bash
go get github.com/djylb/holepunch
```

## Features

- **NAT measurement.** A built-in observer server measures each client's
  mapping, filtering and port allocation from several ports, verifies the
  reported addresses with a return-path cookie, and can add third-party STUN
  observations as a second view.
- **One plan per NAT pair.** Cone and restricted NATs connect on the first
  round. Sequential symmetric NATs get port prediction with paired send
  orders. Random symmetric NATs get bounded birthday rounds. Pairs that cannot
  connect fail fast with a reason the caller can act on.
- **Synchronized rounds.** The coordinator aligns both clients' start times
  from their control-link round-trip times and adjusts each round from what
  the previous one observed.
- **Background mode.** When the caller is already relaying, a slow, low-rate
  birthday round raises the chance of a direct path without bursts of
  traffic.
- **Network friendliness.** Every packet is encrypted. Packets have no fixed
  per-session bytes and use per-session length ranges and target orders. The
  first packet of each flow is a standard STUN Binding request, so networks
  that only admit known UDP protocols let the flow through. Send rate, new
  targets and distinct ports are capped per session.
- **Many network shapes.** IPv4 and IPv6, dual stack, same LAN, same host,
  shared upstream NAT, clients on the server's own LAN, UPnP/NAT-PMP/PCP port
  mapping, and overlay interfaces such as Tailscale or WireGuard (ranked last,
  and can be excluded).
- **Several paths.** Optionally hand over more than one confirmed path, for
  example one per address family.
- **Bounded resources.** Every session has hard limits on packets, sockets,
  goroutines and time. Panics in callbacks are contained, and everything is
  released when the session ends.

## Packages

| Package                                     | Contents                                                                 |
|---------------------------------------------|--------------------------------------------------------------------------|
| `github.com/djylb/holepunch`                | client runtime: `AttachSession`, `Options`, `Session`, `Result`, `Error` |
| `github.com/djylb/holepunch/coord`          | coordinator: sessions, planning, round alignment, results and memory     |
| `github.com/djylb/holepunch/natprobe`       | NAT observer server and the registry the coordinator uses                |
| `github.com/djylb/holepunch/portmapper`     | UPnP IGD, NAT-PMP and PCP port mapping                                   |
| `github.com/djylb/holepunch/protocol`       | control messages, NAT traits, plans and reasons shared by both sides     |
| `github.com/djylb/holepunch/controlwire`    | framing of the control connection                                        |
| `github.com/djylb/holepunch/udpwire`        | encrypted UDP datagram codec                                             |
| `github.com/djylb/holepunch/nattest`        | in-process NAT and network simulator for tests                           |
| `github.com/djylb/holepunch/standalone/...` | separate module: a complete server and clients built on the library      |

## Usage

### Client

Open an authenticated, encrypted control connection to the server (TLS works
as is), send whatever the application needs first, then hand the connection
to `AttachSession`:

```go
conn, err := tls.Dial("tcp", "coordinator.example:4343", tlsConfig)
if err != nil {
	return err
}
defer conn.Close() // the connection stays yours; the library never closes it

sess, err := holepunch.AttachSession(ctx, conn, holepunch.Options{})
if err != nil {
	return err // a *holepunch.Error; see "Handling failures" below
}
defer sess.Close()

pc := sess.PacketConn()               // the punched UDP socket, now yours
peer := sess.Result().Path.RemoteAddr // the peer's address on it
_, err = pc.WriteTo([]byte("hello"), net.UDPAddrFromAddrPort(peer))
```

A control connection that is not a `*tls.Conn` but is protected by an outer
layer (an encrypted bridge, a QUIC stream) needs
`Options.ControlSecurity: protocol.ControlSecurityDeclared`. An upper layer
other than QUIC wraps the socket with `udpwire.DropResidual` (see
`Session.ResidualFilter`) so that late handshake packets never reach it.

### Server

A `natprobe.Server` measures the clients' NATs and a `coord.Coordinator`
runs the sessions. Pair two clients' connections in one session:

```go
reg := natprobe.NewRegistry(natprobe.RegistryConfig{})
probe, err := natprobe.NewServer(natprobe.ServerConfig{
	Registry: reg,
	Groups:   []natprobe.ObserverGroup{{Bind: publicIP}},
	BasePort: 3478,
})
// handle err
if err := probe.Start(); err != nil {
	return err
}
defer probe.Close()

co, err := coord.New(coord.Config{Registry: reg, DefaultProbe: probe.ProbeSpec()})
// handle err
defer co.Close()

sess, err := co.NewSession(coord.SessionOptions{})
// handle err
err = sess.Attach(protocol.RoleInitiator, connA, coord.AttachOptions{}) // connA: a TLS conn, handshake done
err = sess.Attach(protocol.RoleResponder, connB, coord.AttachOptions{})
```

Once `Attach` returns nil the connection belongs to the session, which closes
it when the session ends. `Config.OnResult` receives every session's outcome.

### Clients on the server's LAN

A client that reaches the server over a LAN route, or through a router
hairpin that keeps the source address, is seen at its private address
(`protocol.Traits.LANObserved`; the result warns `lan_observed` and the
client's diagnostics carry the hint `server_sees_lan`). Two such clients on one
LAN connect over it. With a peer elsewhere, the server knows no public address
of the LAN client, so by default it is reached at the addresses its STUN
servers and port mapping reported, with direct sends only and a small packet
cap. `coord.Config.VerifiedTargetsOnly` (`holepunchd -verified-targets-only`)
refuses such self-reported addresses. Letting the server see these clients at
their public address (a hairpin with source NAT, or no LAN route to the
server's public IP) avoids the restriction altogether.

The package examples run the whole flow on a simulated Internet
(`go test -run Example .`), and the `standalone` module is a complete
deployment with authentication and matchmaking.

### Handling failures

A failed session returns a `*holepunch.Error`. Its `Advice` and the class of
its `Reason` say what to do next:

```go
var herr *holepunch.Error
if errors.As(err, &herr) {
	switch {
	case herr.Advice == protocol.AdviceRelayOnly:
		// no direct path is expected for this pair: keep the relay
	case herr.Advice == protocol.AdviceBackgroundViable:
		// keep relaying and punch again with Options.Mode = protocol.ModeBackground
	case herr.Reason.Class() == protocol.ClassTransient:
		// try again, after herr.RetryAfter when it is set
	default:
		// fatal (configuration, network) or NAT-hard: retrying now ends the same way
	}
}
```

`herr.Diagnostics` holds the full account of the session (the NAT traits of
both sides, the rounds run, packet counters) for logs and support; it is nil
when the session failed before the server started it.

## Standalone server and clients

The `standalone` module builds three commands:

- `holepunchd`: TLS control server with coordinator and NAT observer;
- `holepunch`: TCP forwarding over QUIC on the punched path;
- `holepunch-diag`: connectivity diagnostics.

```bash
git clone https://github.com/djylb/holepunch
cd holepunch/standalone
go install ./cmd/...

# server (prints its certificate pin at start)
holepunchd -listen :4343 -probe-ip 203.0.113.10 -auth-token SECRET

# a host that exposes local services, and a client that connects to it
holepunch host    -server 203.0.113.10:4343 -pin PIN -auth-token SECRET -id home -target 127.0.0.1:22
holepunch connect -server 203.0.113.10:4343 -pin PIN -auth-token SECRET -id home -listen 127.0.0.1:2222
```

The server needs TCP 4343 and UDP 3478-3480 (`-probe-port`, `-probe-ports`)
open. Run any command with `-h` for all flags.

## Testing

```bash
make ci                                       # fmt, vet, lint, race (default and fault-injection builds)
go test ./e2e/                                # end-to-end matrix on simulated NATs
HOLEPUNCH_E2E_LEVEL=nightly go test ./e2e/    # full matrix, ablation and fault runs
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
