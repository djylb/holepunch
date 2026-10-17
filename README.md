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
  observations as a second view. Clients ask up to 8 STUN servers per address
  family at once, so a server that is blocked or slow in the client's region
  (some are unreachable from mainland China, many are far from Africa) costs
  nothing: probing waits at most 150 ms for STUN.
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

| Package                                     | Contents                                                              |
|---------------------------------------------|-----------------------------------------------------------------------|
| `github.com/djylb/holepunch`                | client: `Punch`, `Options`, `Session`, `Result`, `Error`              |
| `github.com/djylb/holepunch/coord`          | coordinator: sessions, planning, round alignment, results and memory  |
| `github.com/djylb/holepunch/natprobe`       | NAT observer server and the registry it shares with the coordinator   |
| `github.com/djylb/holepunch/portmapper`     | UPnP IGD, NAT-PMP and PCP port mapping                                |
| `github.com/djylb/holepunch/protocol`       | control messages, NAT traits, plans and reasons shared by both sides  |
| `github.com/djylb/holepunch/stun`           | STUN Binding messages, a client query and a minimal server            |
| `github.com/djylb/holepunch/udpsock`        | UDP socket helpers: ICMP error reports, TTL / hop limit, truncation   |
| `github.com/djylb/holepunch/hostaddr`       | the host's addresses classified as loopback, LAN, public or overlay   |
| `github.com/djylb/holepunch/clock`          | the time source, with a Fake clock for deterministic tests            |
| `github.com/djylb/holepunch/nattest`        | in-process NAT and network simulator for tests                        |
| `github.com/djylb/holepunch/standalone/...` | separate module: a complete server and clients built on the library   |

`stun`, `udpsock`, `hostaddr` and `clock` depend on the standard library only
and are useful on their own.

## Usage

### Client

Open an authenticated, encrypted control connection to the server (TLS works
as is), send whatever the application needs first, then hand the connection
to `Punch`:

```go
conn, err := tls.Dial("tcp", "coordinator.example:4343", tlsConfig)
if err != nil {
	return err
}
defer conn.Close() // the connection stays yours; the library never closes it

sess, err := holepunch.Punch(ctx, conn, holepunch.Options{})
if err != nil {
	return err // a *holepunch.Error; see "Handling failures" below
}
defer sess.Close()

pc := sess.PacketConn()               // the punched UDP socket, now yours
peer := sess.Result().Path.RemoteAddr // the peer's address on it
_, err = pc.WriteTo([]byte("hello"), net.UDPAddrFromAddrPort(peer))
```

A TLS connection is accepted as it is, its handshake completed first if it
has not run yet. A control connection protected by another outer layer (an
encrypted bridge, a QUIC stream) needs
`Options.ControlSecurity: protocol.ControlSecurityDeclared`. An upper layer
other than QUIC reads through `sess.FilterResidual(pc)`, which drops the
peer's last handshake packets; QUIC needs nothing.

With `Options.MaxPaths` above 1 the session can hand over more than one
confirmed path, for example one per address family: `sess.Result().Paths()`
lists them with their socket, kind of network and keepalive advice, and
`sess.PacketConns()` returns each socket once.

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

spec := probe.ProbeSpec()
spec.STUN, _ = natprobe.ResolveSTUN(ctx, nil, stun.DefaultServers()) // optional, see below
co, err := coord.New(coord.Config{Registry: reg, DefaultProbe: spec})
// handle err
defer co.Close()

sess, err := co.NewSession(coord.SessionOptions{})
// handle err
err = sess.Attach(protocol.RoleInitiator, connA, coord.AttachOptions{}) // connA, connB: TLS conns
err = sess.Attach(protocol.RoleResponder, connB, coord.AttachOptions{})
res, err := sess.Wait(ctx) // the session's outcome
```

Once `Attach` returns nil the connection belongs to the session, which closes
it when the session ends. `Config.OnResult` receives every session's outcome
as well.

STUN servers are optional. `stun.DefaultServers` lists public ones on
several continents, mainland China included; `ResolveSTUN` turns names into
the addresses the protocol carries (resolve again every few hours in a
long-running server, as `holepunchd` does). A long-running server can hand
every session the current list through `coord.Config.Probe` instead of
`DefaultProbe`.

### Servers with a changing public address

A server whose public address changes binds its observers to the wildcard
address with a `Scope` instead of an `Advertise` address
(`natprobe.ObserverGroup{Bind: netip.IPv4Unspecified(), Scope: natprobe.ScopePublic}`),
and gives each client the address it is reached at when it attaches:

```go
spec := probe.ProbeSpecAt(addrTheClientReached)
err = sess.Attach(protocol.RoleResponder, connB, coord.AttachOptions{Probe: &spec})
```

On a host with several addresses of a family, bind each address in its own
group: replies leave from the bound address, which a restricted NAT requires.

### Clients on the server's LAN

A client that reaches the server over a LAN route, or through a router
hairpin that keeps the source address, is seen at its private address
(`protocol.Traits.LANObserved`; the result warns `lan_observed` and the
client's diagnostics carry the hint `server_sees_lan`). Two such clients on one
LAN connect over it. With a peer elsewhere, the server knows no public address
of the LAN client, so by default it is reached at the addresses its STUN
servers and port mapping reported, with direct sends only and a small packet
cap. `coord.Config.Targets: coord.TargetsVerifiedOnly`
(`holepunchd -verified-targets-only`) refuses such self-reported addresses. Letting the server see these clients at
their public address (a hairpin with source NAT, or no LAN route to the
server's public IP) avoids the restriction altogether.

The package examples run the whole flow on a simulated Internet
(`go test -run Example .`), and the `standalone` module is a complete
deployment with authentication and matchmaking.

### Handling failures

A failed session returns a `*holepunch.Error`. Its `Advice` and the class of
its `Reason` say what to do next:

```go
if herr, ok := errors.AsType[*holepunch.Error](err); ok {
	switch {
	case herr.Advice == protocol.AdviceRelayOnly:
		// no direct path is expected for this pair: keep the relay
	case herr.Advice == protocol.AdviceBackgroundViable:
		// keep relaying and punch again in a Background session:
		// coord.SessionOptions.Mode on the server, Options.AcceptBackground here
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

## Tools

The building blocks are packages of their own:

```go
// The public address of a UDP socket, from a STUN server.
mapped, err := stun.Query(ctx, conn, stunServer)

// Windows reports ICMP errors on unconnected UDP sockets; switch them off,
// and read past them when a socket keeps them on.
_ = udpsock.DisableICMPReports(conn)
if udpsock.IsICMPReport(err) { /* an earlier datagram's fate: read on */ }

// The host's addresses, and which ones are on an overlay such as Tailscale.
addrs, err := hostaddr.List()
for _, a := range addrs {
	fmt.Println(a.Addr(), a.Interface, a.Kind) // lan, public, overlay or loopback
}
```

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
open. By default it hands the clients a built-in list of public STUN servers;
`-stun HOST:PORT` (repeatable) replaces it and `-stun none` turns STUN off. Run
any command with `-h` for all flags.

## Testing

`nattest` simulates NATs, routers and links in process: a test runs real
clients, a coordinator and natprobe across it, and with a `clock.Fake`
(`nattest.WithClock`, `Options.Clock`, `coord.Config.Clock`) the whole
deployment advances deterministically, far faster than real time. The
package example shows the setup.

```bash
make ci                                       # fmt, vet, lint, race (default and fault-injection builds)
go test ./e2e/                                # end-to-end matrix on simulated NATs
HOLEPUNCH_E2E_LEVEL=nightly go test ./e2e/    # full matrix, ablation and fault runs
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
