package e2e

import (
	"net/netip"
	"time"

	"github.com/djylb/holepunch/nattest"
)

// The cells of destination-dependent routes: a pair measured on a real
// network, rebuilt with destination-dependent routes (nattest.Route).
//
//   - The PDF side ("SPLITPDF") leaves toward the server and the STUN
//     server through one endpoint-independent mapping at a random port, and
//     toward everybody else, the peer included, through another that keeps
//     the local port; both filter by address and port. natprobe and STUN
//     agree on an EIM side whose observed port is not its local port.
//   - The other side ("PROXYFW") reaches the server through a full cone
//     that keeps the local port, and everybody else — the STUN server and
//     the peer — through a proxy that maps each destination at a random
//     port and admits anyone (nattest.Route.Proxy); a host firewall behind
//     it admits only the endpoints the socket sent to. natprobe sees an EIM
//     side with port-dependent filtering, STUN another port: path
//     dependent, planned as random.
//
// The PDF side's packets reach the proxy side once that side sent to the
// PDF side's local port (the local-port candidate), and the replies
// leave through proxy mappings the PDF side never sent to: physically a
// PDF×RND pair. The Interactive cell must reach the birthday model, the
// Background one 0.8 of it, without a scan ban.

// splitPDF is the PDF side's NAT: the server's and the STUN server's
// addresses on a random-port path of their own.
func splitPDF(w *world) nattest.NATConfig {
	c := profPRC()
	c.Name = "splitpdf"
	c.Routes = []nattest.Route{{Dst: hostPrefixes(append(w.server.Addrs(), w.stun.Addr())...),
		Mapping: nattest.EIM, Filtering: nattest.APDF, PortAlloc: nattest.Random}}
	return c
}

// proxyFW is the proxy side: its router's full cone toward the server, its
// proxy toward everybody else, and the host firewall behind them.
func proxyFW(w *world) []nattest.NATConfig {
	router := nattest.FullCone()
	router.Name = "proxyrouter"
	router.Routes = []nattest.Route{
		{Dst: hostPrefixes(w.server.Addrs()...), Mapping: nattest.EIM, Filtering: nattest.EIF, PortAlloc: nattest.Preserve},
		{Dst: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, Mapping: nattest.APDM, Filtering: nattest.EIF,
			PortAlloc: nattest.Random, Proxy: true},
	}
	host := nattest.NATConfig{Name: "hostfw", Mapping: nattest.Identity, Filtering: nattest.APDF}
	return []nattest.NATConfig{router, host}
}

// splitRoutePair builds the PDF side as initiator and the proxy side as
// responder, each NAT with scan detection when scan is set.
func splitRoutePair(scan bool) func(*world) [2]*side {
	return func(w *world) [2]*side {
		a, b := []nattest.NATConfig{splitPDF(w)}, proxyFW(w)
		if scan {
			for _, cs := range [][]nattest.NATConfig{a, b} {
				for i := range cs {
					cs[i].ScanDefense = &nattest.ScanDefense{}
				}
			}
		}
		return [2]*side{w.behind(a), w.behind(b)}
	}
}

// splitRouteWorld runs a STUN server and gives the Interactive ladder its four
// rounds.
func splitRouteWorld(wc *worldConfig) {
	wc.stun = true
	wc.timeouts = e2eTimeouts()
	wc.timeouts.MaxRounds = 4
	wc.timeouts.HandshakeTimeoutMs = 12000
}

// routeCells are the destination-dependent route cells.
func routeCells() []*cell {
	return []*cell{
		{name: "routes/SPLITPDF-PROXYFW", group: "routes", class: classModel, hard: [2]bool{false, true}, modelFactor: 1,
			world: splitRouteWorld, build: splitRoutePair(false), extraTime: 6 * time.Second},
		{name: "bgroutes/SPLITPDF-PROXYFW", group: "bgroutes", class: classModel, hard: [2]bool{false, true},
			world: func(wc *worldConfig) { wc.stun = true }, build: splitRoutePair(true), session: background, plannedModel: true},
	}
}
