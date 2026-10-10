package plan

import (
	"net/netip"
	"slices"

	"github.com/djylb/holepunch/protocol"
)

// Fresh sockets. Some endpoint-dependent NATs give a new socket's first mapping
// its local port and only move the later mappings of the same socket
// (AllocPreserveFresh). Such a side does not need a birthday: it binds a few
// fresh sockets at ports both sides draw from the initiator's spray seed of the
// round — the pair seed of a paired predict stage, the one seed both sides
// share — and each sends to its peer once; the peer aims at exactly those ports
// on the side's public IP (fresh_peer). Two such sides each bind the same drawn
// ports and pair them up: socket k of one side aims at port k of the other.

// minFreshPort is the lowest port a fresh socket is bound at: below it lie
// the ports local services commonly listen on, where the bind would fail.
const minFreshPort = 10000

// FreshPorts returns the count local ports the fresh sockets of a round are
// bound at, drawn from the round's pair seed: the same list on both sides,
// distinct, within [10000, 65535], without sensitive ports and without a
// run of more than three consecutive ports. A port the host cannot bind is
// skipped there and counted as a bind failure; its peer still aims at it.
func FreshPorts(pairSeed [8]byte, count int) []uint16 {
	if count <= 0 {
		return nil
	}
	r := substream(pairSeed, "fresh")
	vals := randomPortValues(r, minFreshPort, 65535, count, func(p uint16) bool { return avoidPort(p, nil) })
	return limitConsecutive(r, vals)
}

// FreshPackets is what a fresh or fresh_peer stage sends: Repeats packets
// from each of Count sockets to each target (or to the paired port), or
// Repeats packets to each of the Count drawn ports. Any other stage is 0.
func FreshPackets(st protocol.Stage) int {
	reps := int(max(st.Repeats, 1))
	switch st.Kind {
	case protocol.StageFresh:
		return int(st.Count) * reps * max(len(st.Targets), 1)
	case protocol.StageFreshPeer:
		return int(st.Count) * reps
	}
	return 0
}

// preserveFresh reports whether a side's fresh sockets keep their local
// ports for their first mapping, as far as planning goes: natprobe saw it
// on at least one probing socket (Medium) and the mapping is endpoint
// dependent on one exit.
func preserveFresh(t protocol.Traits) bool {
	return t.Mapping == protocol.MapAPDM && !t.MultiExit && t.PortAlloc == protocol.AllocPreserveFresh &&
		t.PortAllocConf >= protocol.ConfMedium
}

// freshPairClass replaces a birthday ladder by the fresh-socket one where
// the random side keeps a fresh socket's port: PDF × such a side, and two
// such sides. Every other pair keeps its class: an OPEN peer needs no
// prediction, and a sequential or truly random peer cannot be aimed at
// from a fresh socket.
func freshPairClass(pairClass string, a, b protocol.Traits) string {
	switch {
	case pairClass == PairPDFRnd && (preserveFresh(a) || preserveFresh(b)):
		return PairPDFPres
	case pairClass == PairRndRnd && preserveFresh(a) && preserveFresh(b):
		return PairPresPres
	}
	return pairClass
}

// freshStage resolves a fresh template stage for one side (phase 1): its
// own fresh sockets when it keeps their ports — paired with the peer's
// when the peer does too, aimed at the peer's first Direct target
// otherwise — or the stage aiming at the peer's fresh sockets. nil when
// neither side keeps fresh ports or there is nothing to aim at.
func freshStage(st stageTmpl, ttl uint8, self, peer protocol.Traits, targets []netip.AddrPort, ip netip.Addr, blocked bool) *protocol.Stage {
	out := protocol.Stage{AtMs: st.atMs, Count: st.count, Repeats: st.repeats, TTL: ttl}
	switch {
	case preserveFresh(self) && preserveFresh(peer) && ip.IsValid() && !blocked:
		out.Kind, out.IP = protocol.StageFresh, ip
	case preserveFresh(self) && len(targets) > 0:
		out.Kind, out.Targets = protocol.StageFresh, []netip.AddrPort{targets[0]}
	case preserveFresh(peer) && ip.IsValid() && !blocked:
		out.Kind, out.IP = protocol.StageFreshPeer, ip
	default:
		return nil
	}
	return &out
}

// fitFresh cuts a fresh stage to the sockets and packets it was granted;
// nil when not even one socket or port is left. The stage is copied.
func fitFresh(st *protocol.Stage, sockets, packets int) *protocol.Stage {
	if st == nil {
		return nil
	}
	out := *st
	per := FreshPackets(protocol.Stage{Kind: out.Kind, Count: 1, Repeats: out.Repeats, Targets: out.Targets})
	n := min(int(out.Count), packets/max(per, 1))
	if out.Kind == protocol.StageFresh {
		n = min(n, sockets)
	}
	if n <= 0 {
		return nil
	}
	out.Count = uint16(n)
	return &out
}

// freshPorts is how many destinations a fresh stage adds to the side's
// Direct stages, the new targets it takes from the side's grant: its
// targets that no Direct stage aims at — a side's fresh sockets aim at the
// peer's first Direct target — or the Count ports it draws on the peer's
// IP.
func freshPorts(st *protocol.Stage, direct []protocol.Stage) int {
	switch {
	case st == nil:
		return 0
	case st.Kind == protocol.StageFresh && len(st.Targets) > 0:
		n := 0
		for _, t := range st.Targets {
			if !slices.ContainsFunc(direct, func(d protocol.Stage) bool { return d.Kind == protocol.StageDirect && slices.Contains(d.Targets, t) }) {
				n++
			}
		}
		return n
	}
	return int(st.Count)
}
