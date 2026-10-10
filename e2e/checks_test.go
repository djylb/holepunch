package e2e

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/djylb/holepunch/internal/netaddr"
	"github.com/djylb/holepunch/protocol"
)

// Assertions of the shared-network cells: dual stack, a shared LAN, a shared
// upstream NAT and two clients on one host.

// Same-LAN limits of a round: the LAN Direct stage comes
// first, fires at once with the normal TTL, aims at no more than four
// targets and sends each at most two packets.
const (
	maxLANTargets = 4
	maxLANRepeats = 2
	// maxUpstreamPerRound bounds the packets to one upstream-LAN candidate
	// in a round.
	maxUpstreamPerRound = 2
	// Unverified-family limits: Direct only, at most four targets,
	// eight packets each, one socket.
	maxUnverifiedTargets = 4
	maxUnverifiedRepeats = 8
)

// summaryPair returns a side's summary pair facts.
func (cr *cellRun) summaryPair(i int) (protocol.PairFacts, error) {
	s := cr.links[i].summary
	if s == nil {
		return protocol.PairFacts{}, fmt.Errorf("%s: no probe_summary", roles[i])
	}
	return s.Pair, nil
}

// lanIPs returns the host's private addresses.
func lanIPs(s *side) []netip.Addr {
	var out []netip.Addr
	for _, a := range s.host.Addrs() {
		if netaddr.Private(a) {
			out = append(out, a)
		}
	}
	return out
}

// checkSameLAN (hairpin group): both sides learn same_lan, every round
// of every running side starts with the LAN Direct stage, and without
// hairpin the session connects to the peer's LAN address (cand_kind lan).
func checkSameLAN(cr *cellRun) error {
	var errs []error
	for i := range 2 {
		p, err := cr.summaryPair(i)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !p.LikelySameLAN[protocol.FamilyUDP4] || !p.SamePublicIP[protocol.FamilyUDP4] {
			errs = append(errs, fmt.Errorf("%s: pair %+v, want same_lan and same_public_ip for udp4", roles[i], p))
		}
		peerLAN := lanIPs(cr.sides[1-i])
		for _, rp := range cr.links[i].plans() {
			for _, s := range rp.Sides {
				if s.Family != protocol.FamilyUDP4 || s.Role == protocol.SideReplyOnly {
					continue
				}
				if err := lanStageFirst(s, peerLAN); err != nil {
					errs = append(errs, fmt.Errorf("%s round %d: %w", roles[i], rp.Round, err))
				}
			}
		}
	}
	if !cr.m.OK {
		return errors.Join(append(errs, errNotSucceeded)...)
	}
	hairpin := false
	for _, n := range cr.sides[0].nats {
		hairpin = hairpin || n.Stats().HairpinDelivered > 0
	}
	if !hairpin {
		for i := range 2 {
			res := cr.r.out[i].sess.Result()
			if !slices.Contains(lanIPs(cr.sides[1-i]), res.Path.RemoteAddr.Addr()) {
				errs = append(errs, fmt.Errorf("%s connected to %v, want the peer's LAN address", roles[i], res.Path.RemoteAddr))
			}
		}
		if cr.m.CandKind != protocol.CandLAN {
			errs = append(errs, fmt.Errorf("cand_kind %q, want %q", cr.m.CandKind, protocol.CandLAN))
		}
	}
	return errors.Join(errs...)
}

// lanStageFirst checks that a side's first stage is the LAN Direct stage.
func lanStageFirst(s protocol.FamilySide, peerLAN []netip.Addr) error {
	if len(s.Stages) == 0 {
		return errors.New("no stages")
	}
	st := s.Stages[0]
	if st.Kind != protocol.StageDirect || st.AtMs != 0 || st.TTL != 0 || len(st.Targets) == 0 ||
		len(st.Targets) > maxLANTargets || st.Repeats > maxLANRepeats {
		return fmt.Errorf("first stage %+v is not the LAN Direct stage", st)
	}
	for _, t := range st.Targets {
		if !slices.Contains(peerLAN, t.Addr()) {
			return fmt.Errorf("LAN stage target %v is not a LAN address of the peer %v", t, peerLAN)
		}
	}
	return nil
}

// checkUpstream checks the shared-upstream cells: the same public IP but
// not the same LAN; no packet to the peer's LAN address; with port mappings,
// the upstream-LAN candidates are pushed as peer_targets{portmap} after every
// go and get at most two packets per round. With port mappings and without
// the carrier's hairpin the session wins on the upstream candidate with
// cand_kind lan; with the hairpin and without port mappings on the peer's
// public mapping; with both, a win on the upstream candidate has cand_kind
// targets. Without either the cell fails (checked by its class).
func checkUpstream(hairpin, pmap bool) func(*cellRun) error {
	return func(cr *cellRun) error {
		var errs []error
		upstream := [2][]netip.AddrPort{}
		for i := range 2 {
			p, err := cr.summaryPair(i)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if !p.SamePublicIP[protocol.FamilyUDP4] || p.LikelySameLAN[protocol.FamilyUDP4] {
				errs = append(errs, fmt.Errorf("%s: pair %+v, want same_public_ip without same_lan", roles[i], p))
			}
			for _, a := range lanIPs(cr.sides[1-i]) {
				if _, sent := cr.r.out[i].host.FirstSendTo[a]; sent {
					errs = append(errs, fmt.Errorf("%s sent to the peer's LAN address %v", roles[i], a))
				}
			}
			rounds := map[uint8]bool{}
			for _, a := range cr.links[i].assists {
				if a.Kind == protocol.AssistPeerTargets && a.Source == protocol.TargetsPortmap {
					rounds[a.Round] = true
					upstream[i] = append(upstream[i], a.Targets...)
				}
			}
			if !pmap {
				continue
			}
			for _, g := range cr.links[i].gos {
				if !rounds[g.msg.Round] {
					errs = append(errs, fmt.Errorf("%s: no peer_targets{portmap} with the go of round %d", roles[i], g.msg.Round))
				}
			}
			// The wrapper sees every packet; replies and the nomination and
			// handover packets to the winner are not initiated, so at least
			// sent − (reply + handshake + handover) of them were.
			sent := cr.sides[i].net.sentTo()
			st := cr.r.out[i].diag.Counters.TxByStage
			other := st["reply"] + st["handshake"] + st["handover"]
			nrounds := max(len(cr.links[i].gos), 1)
			for _, u := range dedup(upstream[i]) {
				if n := sent[u] - other; n > maxUpstreamPerRound*nrounds {
					errs = append(errs, fmt.Errorf("%s: at least %d initiated packets to the upstream candidate %v over %d rounds",
						roles[i], n, u, nrounds))
				}
			}
		}
		if !hairpin && !pmap {
			return errors.Join(errs...)
		}
		if !cr.m.OK {
			return errors.Join(append(errs, errNotSucceeded)...)
		}
		for i := range 2 {
			res := cr.r.out[i].sess.Result()
			isUp := slices.Contains(upstream[i], res.Path.RemoteAddr)
			switch {
			case !hairpin && pmap && !isUp:
				errs = append(errs, fmt.Errorf("%s connected to %v, want an upstream candidate %v", roles[i], res.Path.RemoteAddr, upstream[i]))
			case hairpin && !pmap && !slices.Contains(cr.sides[1-i].publicIPs(), res.Path.RemoteAddr.Addr()):
				errs = append(errs, fmt.Errorf("%s connected to %v, want the peer's public mapping", roles[i], res.Path.RemoteAddr))
			}
		}
		switch {
		case !hairpin && pmap && cr.m.CandKind != protocol.CandLAN:
			errs = append(errs, fmt.Errorf("cand_kind %q, want %q", cr.m.CandKind, protocol.CandLAN))
		case hairpin && pmap && cr.m.CandKind != protocol.CandTargets && slices.Contains(upstream[0], cr.r.out[0].sess.Result().Path.RemoteAddr):
			errs = append(errs, fmt.Errorf("won on the upstream candidate with cand_kind %q, want %q", cr.m.CandKind, protocol.CandTargets))
		}
		return errors.Join(errs...)
	}
}

func dedup(in []netip.AddrPort) []netip.AddrPort {
	slices.SortFunc(in, func(a, b netip.AddrPort) int { return a.Compare(b) })
	return slices.Compact(in)
}

// checkUnverifiedV6 checks the cell where the server observes IPv4 only and
// both clients are dual stack. IPv6 runs unverified: pair.unverified[udp6],
// the warning unverified_targets, a no_probe_endpoint report with the primary
// socket's local address only, Direct stages only (light, one socket, at most
// four targets of eight packets each) — and IPv6 carries verified peer
// packets.
func checkUnverifiedV6(cr *cellRun) error {
	var errs []error
	if !slices.Contains(cr.r.res.Warn, protocol.WarnUnverifiedTargets) {
		errs = append(errs, fmt.Errorf("coordinator warn %v lacks %s", cr.r.res.Warn, protocol.WarnUnverifiedTargets))
	}
	for i := range 2 {
		p, err := cr.summaryPair(i)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !p.Unverified[protocol.FamilyUDP6] || p.Unverified[protocol.FamilyUDP4] {
			errs = append(errs, fmt.Errorf("%s: unverified %v, want udp6 only", roles[i], p.Unverified))
		}
		if len(p.SharedFamilies) == 0 || p.SharedFamilies[0] != protocol.FamilyUDP6 {
			errs = append(errs, fmt.Errorf("%s: shared families %v, want udp6 first", roles[i], p.SharedFamilies))
		}
		if rep := cr.links[i].report; rep != nil {
			found := false
			for _, f := range rep.Families {
				if f.Family != protocol.FamilyUDP6 {
					continue
				}
				found = true
				if f.Failure != protocol.ReasonNoProbeEndpoint || len(f.Sockets) != 1 || len(f.Sockets[0].Rows) != 0 || !f.Sockets[0].Local.IsValid() {
					errs = append(errs, fmt.Errorf("%s: udp6 report %+v, want no_probe_endpoint with the primary socket's local address", roles[i], f))
				}
			}
			if !found {
				errs = append(errs, fmt.Errorf("%s: probe_report has no udp6 family", roles[i]))
			}
		}
		for _, rp := range cr.links[i].plans() {
			for _, s := range rp.Sides {
				if s.Family != protocol.FamilyUDP6 || s.Role == protocol.SideReplyOnly {
					continue
				}
				if s.Sockets > 1 {
					errs = append(errs, fmt.Errorf("%s round %d: udp6 side with %d sockets", roles[i], rp.Round, s.Sockets))
				}
				targets := 0
				for _, st := range s.Stages {
					switch st.Kind {
					case protocol.StageDirect:
						targets += len(st.Targets)
						if st.Repeats > maxUnverifiedRepeats {
							errs = append(errs, fmt.Errorf("%s round %d: %d repeats to unverified targets", roles[i], rp.Round, st.Repeats))
						}
					case protocol.StageReplyOnly:
					default:
						errs = append(errs, fmt.Errorf("%s round %d: %s stage in the unverified family", roles[i], rp.Round, st.Kind))
					}
				}
				if targets > maxUnverifiedTargets {
					errs = append(errs, fmt.Errorf("%s round %d: %d unverified targets", roles[i], rp.Round, targets))
				}
				if s.Sandwich {
					errs = append(errs, fmt.Errorf("%s round %d: sandwich in the unverified family", roles[i], rp.Round))
				}
			}
		}
		if !cr.m.OK {
			continue
		}
		rx := 0
		for _, f := range cr.r.out[i].diag.Families {
			if f.Family == protocol.FamilyUDP6 {
				rx = f.Counters.RxVerified
			}
		}
		if rx == 0 {
			errs = append(errs, fmt.Errorf("%s: no verified IPv6 peer packet", roles[i]))
		}
	}
	return errors.Join(errs...)
}

// checkV4OnlyClient checks the cell where the server is dual stack and one
// client IPv4 only: udp4 is the only shared family, nothing is unverified and
// the session succeeds on IPv4.
func checkV4OnlyClient(cr *cellRun) error {
	var errs []error
	for i := range 2 {
		p, err := cr.summaryPair(i)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !slices.Equal(p.SharedFamilies, []protocol.Family{protocol.FamilyUDP4}) || len(p.Unverified) != 0 {
			errs = append(errs, fmt.Errorf("%s: pair %+v, want udp4 alone, verified", roles[i], p))
		}
	}
	if cr.m.OK && cr.m.Family != protocol.FamilyUDP4 {
		errs = append(errs, fmt.Errorf("won on %s", cr.m.Family))
	}
	return errors.Join(errs...)
}
