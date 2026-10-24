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
| `github.com/djylb/holepunch/plan`           | the planner contract: `Planner` and the values it reads and returns   |
| `github.com/djylb/holepunch/portmapper`     | UPnP IGD, NAT-PMP and PCP port mapping                                |
| `github.com/djylb/holepunch/protocol`       | control messages, NAT traits, plans and reasons shared by both sides  |
| `github.com/djylb/holepunch/stun`           | STUN Binding messages, a client query and a minimal server            |
| `github.com/djylb/holepunch/udpsock`        | UDP socket helpers: ICMP error reports, TTL / hop limit, truncation   |
| `github.com/djylb/holepunch/hostaddr`       | the host's addresses classified as loopback, LAN, public or overlay   |
| `github.com/djylb/holepunch/clock`          | the time source, with a Fake clock for deterministic tests            |
| `github.com/djylb/holepunch/nattest`        | in-process NAT and network simulator for tests                        |
| `github.com/djylb/holepunch/quicpath`       | separate module: QUIC over the punched paths, with pinned peers       |
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

pc := sess.PacketConn()               // the punched UDP socket
peer := sess.Result().Path.RemoteAddr // the peer's address on it
_, err = pc.WriteTo([]byte("hello"), net.UDPAddrFromAddrPort(peer))
```

When `Punch` returns, the library is done with the socket: it never reads or
writes it again, and its deadlines and TTL are back to normal, so read and
write it freely. The `Session` still owns it until `Close`, which releases
the socket's port mapping (if any) and closes it; `sess.Detach()` instead
hands the sockets and the mapping releases over, after which `Close` does
nothing and closing them is up to you.

A TLS connection is accepted as it is, its handshake completed first if it
has not run yet. A control connection protected by another outer layer (an
encrypted bridge, a QUIC stream) needs
`Options.ControlSecurity: protocol.ControlSecurityDeclared`. An upper layer
other than QUIC reads through `sess.FilterResidual(pc)`, which drops the
peer's last handshake packets; QUIC needs nothing, and the `quicpath`
module runs it over the session's paths with the peer's certificate pinned.

With `Options.MaxPaths` above 1 the session can hand over more than one
confirmed path, for example one per address family: `sess.Result().Paths()`
lists them with their socket, kind of network and keepalive advice, and
`sess.PacketConns()` returns each socket once.

`Options.Logger` (a `*slog.Logger`) logs each session's milestones — the
start, phase transitions, rounds, the confirmation and handover — and its
failure with reason, detail and advice; tokens and routes never appear.

### The control channel

The control channel is any reliable, ordered stream that you have
authenticated and that has `net.Conn` deadline semantics (a deadline in the
past makes a blocked `Read` or `Write` return a timeout at once). TLS over TCP
is the common case; a stream of a multiplexed connection the application
already runs (a QUIC stream, a stream of its own multiplexer over TLS) works
too, with `ControlSecurityDeclared`. Each session needs a stream of its own.

The coordinator need not be a separate server. An application server that
already holds both clients' connections runs `coord` in process and attaches
one stream per client; a client can even host the coordinator itself and
talk to its own `Punch` over `net.Pipe`:

```go
clientEnd, coordEnd := net.Pipe()
err := sess.Attach(protocol.RoleInitiator, coordEnd,
	coord.AttachOptions{Security: protocol.ControlSecurityDeclared})
// handle err
local, err := holepunch.Punch(ctx, clientEnd,
	holepunch.Options{ControlSecurity: protocol.ControlSecurityDeclared})
```

The server decides each session: the policy, the timeouts and the observers
come in its `punch_start`. `Options.Policy` can only tighten the server's
policy (`protocol.Tighten`), and every timeout is clamped to the protocol's
range (`protocol.Timeouts.Normalize`).

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
the addresses the protocol carries. A long-running server keeps them fresh
with a `natprobe.STUNList` and hands every session the current list through
`coord.Config.Probe`:

```go
stunList := natprobe.NewSTUNList(natprobe.STUNListConfig{Servers: stun.DefaultServers()})
_ = stunList.Refresh(ctx) // the first resolution, before serving
go stunList.Run(ctx)      // again every 6 h
src := natprobe.SpecSource{Server: probe, STUN: stunList}
co, err := coord.New(coord.Config{Registry: reg, Probe: coord.ProbeFrom(src)})
```

A group marked `ObserverGroup.Optional` is skipped when its sockets cannot be
bound (an IPv6 group on a host without IPv6), so one configuration serves
every host; `ServerStats.SkippedGroups` counts the skipped ones.

### Server addresses known per session

One set of observer sockets can be announced at several addresses: each is
probed by the clients as an observer group of its own, so a server can offer
every address a client might reach it at — its public address, the address
the client connected to, a DDNS name's address, the LAN address of clients
on its own network. Fixed addresses go in `ObserverGroup.Advertise`;
addresses known only per session fill the group's free `Slots`:

```go
probe, err := natprobe.NewServer(natprobe.ServerConfig{
	Registry: reg,
	Groups:   []natprobe.ObserverGroup{{Bind: netip.IPv4Unspecified(), Slots: 3}},
	BasePort: 3478,
})
// ...
spec := probe.ProbeSpecAt(currentPublicIP, addrTheClientConnectedTo)
err = sess.Attach(protocol.RoleResponder, connB, coord.AttachOptions{Probe: &spec})
```

`natprobe.ServerAddrs` collects those addresses: configured public ones, a
DNS name's (looked up again every few minutes) and, with `HostPublic`, the
host's global interface addresses. `SpecSource.SpecFor(conn)` puts the
address the client's control connection reached first:

```go
addrs := natprobe.NewServerAddrs(natprobe.ServerAddrsConfig{Names: []string{"punch.example.net"}, HostPublic: true})
go addrs.Run(ctx)
src := natprobe.SpecSource{Server: probe, STUN: stunList, Addrs: addrs}
// for each client:
spec := src.SpecFor(conn)
err = sess.Attach(role, conn, coord.AttachOptions{Probe: &spec})
```

A socket bound to the wildcard address replies from the address each probe
was sent to (Linux, macOS, FreeBSD, OpenBSD, Windows), so a host whose
address changes, or that has several, needs no rebinding. Whether an
observation is evidence of a client's public mapping or of a LAN path
follows each announced address, or `ObserverGroup.Scope` when set.

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

### Without an observer

`coord.Config.NoObserver` runs the coordinator without natprobe. Nothing about
the clients is then verified, so by design the sessions only aim Direct
stages at the public addresses the clients report themselves (from their STUN
servers and port mappings; at most 16, 8 packets each per round): no port
prediction and no birthday rounds, which a client could otherwise point at a
third party's address. Pairs that need prediction (symmetric NATs) need the
observer.

The package examples run the whole flow on a simulated Internet
(`go test -run Example .`), and the `standalone` module is a complete
deployment with authentication and matchmaking.

### Custom planners

The coordinator plans every session with a `plan.Planner`:
`coord.DefaultPlanner()` unless `coord.Config.Planner` sets one. A custom
planner usually wraps the built-in one and changes only what it means to; the
coordinator clamps every decision to the budgets and the protocol limits
whatever the planner returns, and falls back to the built-in planner if it
panics:

```go
type relayFirst struct{ plan.Planner }

// Classify sends the pairs classified rnd_x_rnd straight to the relay.
func (p relayFirst) Classify(in plan.ClassifyInput) plan.Classification {
	cl := p.Planner.Classify(in)
	if cl.PairClass == "rnd_x_rnd" {
		cl.Reject = protocol.ReasonHardSymmetricRandom
	}
	return cl
}

co, err := coord.New(coord.Config{Registry: reg, DefaultProbe: spec,
	Planner: relayFirst{coord.DefaultPlanner()}})
```

`coord.Config.Memory` takes a `coord.StrategyMemory` of your own in the same
way, for example one shared by several servers.

### Handling failures

A failed session returns a `*holepunch.Error`. Its `Advice`, its `Reason`
and `RetryAfter` say what to do next; `holepunch.NextAttempt` turns them into
a retry policy with jittered exponential backoff:

```go
next := holepunch.NextAttempt(err, failures) // failures: consecutive, this one included
switch next.Action {
case holepunch.ActionRetry:
	// try again in the same mode after next.Delay (never before RetryAfter)
case holepunch.ActionBackground:
	// keep relaying and punch again after next.Delay in a Background session:
	// coord.SessionOptions.Mode on the server, Options.AcceptBackground here
case holepunch.ActionRelayOnly:
	// no direct path is expected for this pair: keep the relay for next.Delay (hours)
case holepunch.ActionGiveUp:
	// canceled by you, or a configuration or version error: retrying ends the same way
}
```

The server sees the same failure in `coord.Result.Retry`.

The error's `Diagnostics` holds the full account of the session (the NAT traits of
both sides, the rounds run, packet counters) for logs and support; it is nil
when the session failed before the server started it.

### Reconnecting and new paths

A session ends once its paths are handed over; the library keeps no
connection to the peer afterwards. Keeping a link alive is the upper layer's
job, following each path's `Keepalive` advice:

- Ask for spare paths up front with `Options.MaxPaths` (one per family or
  kind of network), so that losing one path leaves another to move to.
- When every path is gone, keep the traffic on the relay and run a new
  session over a new control stream (a new stream of the same multiplexed
  connection will do). Nobody waits for it, so offer it as a
  Background session (`coord.SessionOptions.Mode`, `Options.AcceptBackground`),
  which lets a hard pair take its time; move the traffic once it succeeds.
- The same works to upgrade a relayed link that never punched, paced by
  `NextAttempt`.

Every session is independent: new sockets, new port mappings, its own
`Session` to close or `Detach`.

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
