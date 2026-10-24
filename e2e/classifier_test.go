package e2e

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/ablation"
	"github.com/djylb/holepunch/internal/goroutines"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/stun"
)

// Cells of situations measured on real networks:
//
//   - classify/…, bgclassify/…: one side sits behind an outbound protocol
//     classifier that cuts a flow after five datagrams unless one of them
//     was a STUN message (nattest.Classifier). With the flow opener the
//     sessions connect and the confirmed path carries sustained data after
//     the handover (checkSustained); without it (ablation NoOpener) they
//     fail, which TestClassifierOpener measures.
//   - pathdep/…, stun/…: NATs that map the server's address apart from
//     every other destination (a nattest.Route of their own), so natprobe
//     sees a mapping the peer never does. Two rounds without contact make
//     the planner treat the sides as endpoint dependent; a STUN
//     server outside the split shows the other mapping, which the peer
//     then aims at and which marks the side path dependent from the first
//     round.

// classified adds the protocol classifier to a profile.
func classified(f func() nattest.NATConfig) func() nattest.NATConfig {
	return func() nattest.NATConfig {
		c := f()
		c.Classifier = &nattest.Classifier{}
		return c
	}
}

// pathSplit is a profile whose NAT maps the server's addresses apart, by
// its own rules.
func pathSplit(w *world, f func() nattest.NATConfig) nattest.NATConfig {
	c := f()
	c.Routes = append(c.Routes, nattest.Route{Dst: hostPrefixes(w.server.Addrs()...), Mapping: c.Mapping, Filtering: c.Filtering, PortAlloc: c.PortAlloc})
	return c
}

// hostPrefixes are the host prefixes of addresses.
func hostPrefixes(as ...netip.Addr) []netip.Prefix {
	var out []netip.Prefix
	for _, a := range as {
		if a.IsValid() {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

// splitPair builds two sides, each behind its profile, path-split where
// split says so.
func splitPair(a, b func() nattest.NATConfig, split [2]bool) func(*world) [2]*side {
	return func(w *world) [2]*side {
		var out [2]*side
		for i, f := range [2]func() nattest.NATConfig{a, b} {
			c := f()
			if split[i] {
				c = pathSplit(w, f)
			}
			out[i] = w.behind([]nattest.NATConfig{c})
		}
		return out
	}
}

// pathDepWorld gives the no-contact escalation room: two rounds without
// contact, then the rungs of the new ladder.
func pathDepWorld(wc *worldConfig) {
	wc.timeouts = e2eTimeouts()
	wc.timeouts.MaxRounds = 4
	wc.timeouts.HandshakeTimeoutMs = 12000
}

// classifierCells are the protocol-classifier and path-dependent cells.
func classifierCells() []*cell {
	prc, seq, rnd := profPRC, profSYMSEQ, profSYMRND
	out := []*cell{
		{name: "classify/PRC+CLS-SYMSEQ", group: "classify", class: classShould, maxMedianRound: 2,
			build: single(classified(prc), seq), check: checkSustained},
		{name: "classify/SYMSEQ+CLS-PRC", group: "classify", class: classShould, maxMedianRound: 2,
			build: single(classified(seq), prc), check: checkSustained},
		{name: "classify/PRC-PRC+CLS", group: "classify", class: classMust,
			build: single(prc, classified(prc)), check: checkSustained},
		{name: "bgclassify/PRC+CLS-SYMRND", group: "bgclassify", class: classModel, hard: [2]bool{false, true},
			build: single(classified(prc), rnd), session: background, plannedModel: true, check: checkSustained},
	}
	// Path-dependent mapping: the summary's endpoints are no path the peer
	// can use, so the first two easy rounds find nothing and the third
	// pairs fresh sockets. Degraded: the two lost rounds are the
	// price, gated on the should thresholds with their time added.
	lost := 1800*time.Millisecond + 2*ctlMax
	out = append(out,
		&cell{name: "pathdep/PRCSPLIT-PRCSPLIT", group: "pathdep", class: classDegraded, base: classShould, maxMedianRound: 3,
			world: pathDepWorld, build: splitPair(prc, prc, [2]bool{true, true}), extraTime: lost},
		&cell{name: "pathdep/PRCSPLIT-PRC", group: "pathdep", class: classDegraded, base: classShould, maxMedianRound: 3,
			world: pathDepWorld, build: splitPair(prc, prc, [2]bool{true, false}), extraTime: lost},
		// With a STUN server outside the split the client reports the
		// other mapping: the side is path dependent from the summary on,
		// and the peer aims at the STUN mapping in the first round.
		&cell{name: "stun/PRCSPLIT-PRC", group: "stun", class: classShould, maxMedianRound: 1,
			world: func(wc *worldConfig) { pathDepWorld(wc); wc.stun = true }, build: splitPair(prc, prc, [2]bool{true, false})},
	)
	return out
}

// sustainedDatagrams is how many datagrams checkSustained sends each way;
// the classifier would cut a flow after its fifth.
const sustainedDatagrams = 40

// checkSustained sends sustainedDatagrams over the confirmed path each way
// after the handover, through the sockets the caller now owns, and wants
// them all: the classifier of a classify cell lets the flow through for
// good only when it opened with a STUN message. An unsuccessful run
// is the pass rate's business.
func checkSustained(cr *cellRun) error {
	if !cr.m.OK {
		return nil
	}
	r := cr.r
	for from := range 2 {
		to := 1 - from
		src, dst := r.out[from].handed, r.out[to].handed
		if src == nil || dst == nil {
			return fmt.Errorf("%s: no handed-over socket", roles[from])
		}
		peer := r.out[from].sess.Result().Path.RemoteAddr
		for k := range sustainedDatagrams {
			msg := fmt.Appendf(nil, "sustained %d", k)
			if _, err := src.WriteToUDPAddrPort(msg, peer); err != nil {
				return fmt.Errorf("%s: write %d: %w", roles[from], k, err)
			}
		}
		got := 0
		if d, ok := dst.(interface{ SetReadDeadline(time.Time) error }); ok {
			buf := make([]byte, 2048)
			_ = d.SetReadDeadline(time.Now().Add(scaled(time.Second)))
			for got < sustainedDatagrams {
				n, _, err := dst.ReadFromUDPAddrPort(buf)
				if err != nil {
					break
				}
				if strings.HasPrefix(string(buf[:n]), "sustained ") {
					got++
				}
			}
			_ = d.SetReadDeadline(time.Time{})
		}
		if got < sustainedDatagrams {
			return fmt.Errorf("%s → %s: %d of %d datagrams after the handover", roles[from], roles[to], got, sustainedDatagrams)
		}
	}
	return nil
}

// stunServer answers STUN Binding Requests with the requester's
// XOR-MAPPED-ADDRESS (RFC 8489, section 14.2), on its own public host: a third
// party next to the server, on no route of the server's.
func (w *world) stunServer(t testing.TB) netip.AddrPort {
	h := w.n.PublicHost(netip.IPv4Unspecified())
	addr := netip.AddrPortFrom(h.Addrs()[0], 3478)
	pc, err := h.Listen("udp4", addr)
	if err != nil {
		t.Fatalf("stun server: %v", err)
	}
	w.helpers.Add(2)
	go func() {
		defer w.helpers.Done()
		<-w.quit
		_ = pc.Close()
	}()
	go func() {
		defer w.helpers.Done()
		defer func() { _ = pc.Close() }()
		_ = stun.Serve(pc)
	}()
	return addr
}

// classifierRuns is how many runs TestClassifierOpener makes of each cell
// and configuration: the proof needs a handful, not a pass rate.
func classifierRuns() int {
	if suite().level == levelNightly {
		return 5
	}
	return 2
}

// TestClassifierOpener measures what the flow opener is worth behind the
// protocol classifier: every classify cell with the opener and
// without it (ablation NoOpener). With it the runs connect and carry the
// sustained data; without it no run does — the classifier cuts the
// handshake or the data after the fifth datagram of the flow. The result
// goes to classifier_report.md.
func TestClassifierOpener(t *testing.T) {
	var cs []*cell
	for _, c := range classifierCells() {
		// The Background cell runs about a minute each time: nightly, or
		// when selected by name.
		long := c.group == "bgclassify" && suite().level == levelPR && suite().cells == nil
		if (c.group == "classify" || c.group == "bgclassify") && suite().selected(c.name) && !long {
			cs = append(cs, c)
		}
	}
	if len(cs) == 0 {
		t.Skip("no classifier cell selected")
	}
	runs := classifierRuns()
	var mu sync.Mutex
	lines := map[string]string{}
	t.Run("cells", func(t *testing.T) {
		for _, c := range cs {
			t.Run(c.name, func(t *testing.T) {
				t.Parallel()
				release := acquireSlot()
				defer release()
				var good [2]int
				for k, abl := range []ablation.Set{{}, {NoOpener: true}} {
					for i := range runs {
						cr, v := runOnce(t, c, cellSeed(c.name, i), abl, false)
						if cr.m.OK && len(v) == 0 {
							good[k]++
						}
						if k == 0 && len(v) > 0 {
							t.Errorf("full, seed %d: %v", cellSeed(c.name, i), v)
						}
					}
				}
				line := fmt.Sprintf("| %s | %d/%d | %d/%d |", c.name, good[0], runs, good[1], runs)
				mu.Lock()
				lines[c.name] = line
				mu.Unlock()
				t.Log(line)
				switch {
				case c.class != classModel && good[0] < runs:
					t.Errorf("with the opener %d of %d runs connected with sustained data", good[0], runs)
				case c.class == classModel && good[0] == 0:
					t.Errorf("with the opener no run of %d connected", runs)
				}
				if good[1] != 0 {
					t.Errorf("without the opener %d of %d runs connected with sustained data", good[1], runs)
				}
			})
		}
	})
	if dir := suite().out; dir != "" {
		var sb strings.Builder
		sb.WriteString("# Flow opener behind an outbound protocol classifier\n\n")
		_, _ = fmt.Fprintf(&sb, "%d runs per cell and configuration; a run counts when the session connected and %d datagrams each way passed after the handover.\n\n", runs, sustainedDatagrams)
		sb.WriteString("| cell | with opener | NoOpener |\n|---|---|---|\n")
		for _, c := range cs {
			if l, ok := lines[c.name]; ok {
				sb.WriteString(l + "\n")
			}
		}
		if err := writeOut(dir, "classifier_report.md", []byte(sb.String())); err != nil {
			t.Errorf("classifier_report.md: %v", err)
		}
	}
	goroutines.VerifyNone(t)
}

// shapeOpener checks the flow opener per socket: every flow opened
// with a STUN message, and none after a plain packet. It holds for the
// sessions with the opener on (not under the NoOpener ablation).
func shapeOpener(socks []nattest.SocketStats) []string {
	var out []string
	for _, s := range socks {
		if s.PlainFirst > 0 || s.STUNAfterPlain > 0 {
			out = append(out, fmt.Sprintf("socket %v (%s): %d of %d flows opened by a plain packet, %d STUN packets after a plain one",
				s.Local, s.Purpose, s.PlainFirst, s.Flows, s.STUNAfterPlain))
		}
	}
	return out
}
