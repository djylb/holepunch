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
  shared upstream NAT, UPnP/NAT-PMP/PCP port mapping, and overlay interfaces
  such as Tailscale or WireGuard (ranked last, and can be excluded).
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

On the client, pass the authenticated control connection to `AttachSession`:

```go
sess, err := holepunch.AttachSession(ctx, conn, holepunch.Options{
	ControlSecurity: protocol.ControlSecurityDeclared, // conn is authenticated and encrypted
})
if err != nil {
	var herr *holepunch.Error
	if errors.As(err, &herr) {
		// herr.Reason says why; herr.Advice says whether a later attempt is worthwhile.
	}
	return err
}
defer sess.Close()

pc := sess.PacketConn()        // the punched UDP socket
peer := sess.Result().Path.RemoteAddr
```

On the server, a `natprobe.Server` measures the clients and a
`coord.Coordinator` runs the sessions. The `standalone` module shows the whole
server side and client side wired together.

## Standalone server and clients

The `standalone` module builds three commands:

- `holepunchd`: TLS control server with coordinator and NAT observer;
- `holepunch`: TCP forwarding over QUIC on the punched path;
- `holepunch-diag`: connectivity diagnostics.

```bash
go install github.com/djylb/holepunch/standalone/cmd/...@latest

# server (prints its certificate pin at start)
holepunchd -listen :4343 -probe-ip 203.0.113.10 -auth-token SECRET

# a host that exposes local services, and a client that connects to it
holepunch host    -server 203.0.113.10:4343 -pin PIN -auth-token SECRET -id home -target 127.0.0.1:22
holepunch connect -server 203.0.113.10:4343 -pin PIN -auth-token SECRET -id home -listen 127.0.0.1:2222
```

Run any command with `-h` for all flags.

## Testing

```bash
make ci                                       # fmt, vet, lint, race (default and fault-injection builds)
go test ./e2e/                                # end-to-end matrix on simulated NATs
HOLEPUNCH_E2E_LEVEL=nightly go test ./e2e/    # full matrix, ablation and fault runs
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
