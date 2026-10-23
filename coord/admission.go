package coord

import (
	"net/netip"
	"slices"

	"github.com/djylb/holepunch/internal/netaddr"
	"github.com/djylb/holepunch/protocol"
)

// Admission verdicts.
type admitVerdict uint8

const (
	admitRejected admitVerdict = iota
	admitPublic                // a verified IP of the peer
	admitLAN                   // a private address of a peer on the same LAN, or behind the same public IP
	admitOverlay               // an overlay address of a peer that shares an overlay with this side
)

// index builds the admission sets of both sides from their planner views,
// the same sets the clients build from their summaries: the verified IPs
// per family — in an unverified family the first four distinct global
// unicast IPs the side reported — the overlay addresses a peer with an
// overlay may aim at, the private LAN addresses a peer on the same LAN may
// aim at, and the private port-mapping addresses (upstream-LAN candidates)
// a peer behind the same public IP may aim at.
func (ad *admission) index(views [2]protocol.PeerView) {
	for r := range views {
		ad.verified[r] = map[protocol.Family][]netip.Addr{}
		ad.lan[r] = map[protocol.Family][]netip.Addr{}
		ad.overlay[r] = map[protocol.Family][]netip.Addr{}
		ad.upstream[r] = map[protocol.Family][]netip.AddrPort{}
		for _, fv := range views[r].Families {
			unverified, reported := ad.pair.Unverified[fv.Family], 0
			for _, e := range fv.Endpoints {
				ip := e.Addr.Addr()
				switch {
				case e.Source == protocol.EndpointOverlay:
					if len(ad.overlay[r][fv.Family]) < protocol.MaxOverlayTargets && !slices.Contains(ad.overlay[r][fv.Family], ip) {
						ad.overlay[r][fv.Family] = append(ad.overlay[r][fv.Family], ip)
					}
				case e.Verified:
					if !slices.Contains(ad.verified[r][fv.Family], ip) {
						ad.verified[r][fv.Family] = append(ad.verified[r][fv.Family], ip)
					}
				case unverified && netaddr.Public(ip):
					if reported < protocol.MaxReportedIPs && !slices.Contains(ad.verified[r][fv.Family], ip) {
						ad.verified[r][fv.Family] = append(ad.verified[r][fv.Family], ip)
						reported++
					}
				case !netaddr.Private(ip):
				case e.Source == protocol.EndpointLAN:
					if len(ad.lan[r][fv.Family]) < protocol.MaxLANTargets && !slices.Contains(ad.lan[r][fv.Family], ip) {
						ad.lan[r][fv.Family] = append(ad.lan[r][fv.Family], ip)
					}
				case e.Source == protocol.EndpointPortmap:
					ad.addUpstream(r, fv.Family, e.Addr)
				}
			}
		}
	}
}

// addUpstream records a private port-mapping address of side r: an
// upstream-LAN candidate.
func (ad *admission) addUpstream(r int, fam protocol.Family, a netip.AddrPort) {
	if ad.upstream[r] == nil {
		ad.upstream[r] = map[protocol.Family][]netip.AddrPort{}
	}
	if list := ad.upstream[r][fam]; len(list) < protocol.MaxLANTargets && !slices.Contains(list, a) {
		ad.upstream[r][fam] = append(list, a)
	}
}

// admitDirect is the admission of a Direct target a of side p, and the rule
// that refused it: its IP is one the peer verified with a cookie (an
// unverified family: one of the global IPs the peer reported), an
// overlay address the peer reported while both sides have some, a
// private address the peer reported while both sides are on one LAN — the
// same public IP alone is not enough — or a private port mapping of the
// peer behind the same public IP (an upstream-LAN candidate).
func (ad *admission) admitDirect(p int, fam protocol.Family, a netip.AddrPort) (admitVerdict, string) {
	ip := a.Addr()
	switch {
	case !fam.UsableTarget(a):
		return admitRejected, "invalid"
	case slices.Contains(ad.verified[p][fam], ip):
		return admitPublic, ""
	case ad.pair.SharedOverlay[fam] && slices.Contains(ad.overlay[p][fam], ip):
		return admitOverlay, ""
	case !netaddr.Private(ip):
		return admitRejected, "unverified"
	case ad.pair.LikelySameLAN[fam] && slices.Contains(ad.lan[p][fam], ip),
		ad.pair.SamePublicIP[fam] && slices.Contains(ad.upstream[p][fam], a):
		return admitLAN, ""
	}
	return admitRejected, "not_same_lan"
}

// admitIP reports whether ip, a predict, random, fresh or window IP, may be
// aimed at, and the rule that refused it: it must be a verified IP of side p
// in a verified family, and not a private one — a client sprays no LAN
// address, verified or not.
func (ad *admission) admitIP(p int, fam protocol.Family, ip netip.Addr) (bool, string) {
	switch {
	case ad.pair.Unverified[fam]:
		return false, "unverified_family"
	case netaddr.Private(ip):
		return false, "private_ip"
	case fam.Matches(ip) && slices.Contains(ad.verified[p][fam], ip):
		return true, ""
	}
	return false, "unverified_ip"
}

// knownIP reports whether ip is a verified IP of side r for fam.
func (ad *admission) knownIP(r int, fam protocol.Family, ip netip.Addr) bool {
	return slices.Contains(ad.verified[r][fam], ip)
}
