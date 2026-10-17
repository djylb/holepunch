package holepunch

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/djylb/holepunch/internal/candidate"
	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/netaddr"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/protocol"
)

// Assist constants.
const (
	followUpDelay   = 200 * time.Millisecond
	followUpPackets = 3
	followUpGap     = 40 * time.Millisecond
	maxFollowUps    = 4 // concurrent follow-ups; more are dropped
	targetPackets   = 2 // per peer_targets target or window port, each round
)

// Fault-injection point of assist handling.
const fiAssistHandle = "assist.handle"

// carried is what the peer_targets received while no round ran leave for
// the next round: the admitted targets, and per
// family index the targets admission refused (round_result.rejected).
type carried struct {
	targets  []extraTarget
	rejected [2]int
}

// handleAssist consumes one assist from the server in the punching phases:
// peer_seen is evidence about our own packets; peer_targets are re-admitted and
// sent at once in the current round, or carried to the next one when no round
// runs.
func (rt *runtime) handleAssist(a stamped[protocol.Assist], cur *roundRun, pending *carried) {
	if faultinject.Point(fiAssistHandle) != nil || rt.abl.NoAssistRelay {
		return
	}
	switch a.msg.Kind {
	case protocol.AssistRefresh:
		rt.refreshAnchor(a.msg)
	case protocol.AssistPeerSeen:
		if cur != nil {
			rt.onPeerSeen(a.msg, a.at)
		}
	case protocol.AssistPeerTargets:
		targets, rejected := rt.peerTargets(a.msg)
		if cur == nil || cur.ctx.Err() != nil {
			pending.rejected[famIndex(a.msg.Family)] += rejected
			if len(pending.targets)+len(targets) <= pendingAssists*maxRoundTargetsPerAssist {
				pending.targets = append(pending.targets, targets...)
			}
			return
		}
		for _, fr := range cur.fams {
			if fr.w.fam != a.msg.Family {
				continue
			}
			fr.rejected.Add(int32(rejected))
			if room := maxRoundExtras - int(fr.extras.Load()); room > 0 && len(targets) > 0 {
				select {
				case fr.inject <- targets: // the round trims it to the quota, after scattering the window (extraItems)
				default:
				}
			}
		}
	}
}

// maxRoundTargetsPerAssist is the target count of one peer_targets assist
// (the protocol allows at most 16).
const maxRoundTargetsPerAssist = 16

// peerTargets admits the targets and window ports of a peer_targets assist
// (the second admission after the server's). They are
// candidates of kind targets (cand_kind=targets), except an
// upstream-LAN candidate: it ranks with the LAN candidates until
// the hairpin self-test shows that the public path loops back, and then
// below that path. Each gets targetPackets a round, within every
// per-target cap admission sets (LAN 2, unverified family 8). The window
// ports are marked as such: the round that sends them puts them in the
// order of its spray seed (scatterWindows). A drift target is a mapping of
// the peer the server verified while punching: the worker adopts it
// first, so that a new IP of the peer passes like a verified one, in this
// assist and in later plans. rejected counts the targets and window ports
// admission refused.
func (rt *runtime) peerTargets(a protocol.Assist) (out []extraTarget, rejected int) {
	w := rt.fam(a.Family).worker
	if w == nil {
		return nil, 0
	}
	for _, t := range a.Targets {
		t = netaddr.Canon(t)
		if a.Source == protocol.TargetsDrift {
			w.adoptRemap(t)
		}
		if a.Source == protocol.TargetsPortmap && w.admitUpstream(rt, t) {
			k := candidate.KindLAN
			if w.hairpinOK.Load() {
				k = candidate.KindTargets
			}
			rt.punch.notePortmap(t)
			out = append(out, extraTarget{to: t, kind: k})
			continue
		}
		if ok, _ := w.admit(rt, t, protocol.StageDirect); ok {
			if a.Source == protocol.TargetsPortmap {
				rt.punch.notePortmap(t)
			}
			out = append(out, extraTarget{to: t, kind: candidate.KindTargets})
		} else {
			rejected++
		}
	}
	if win := a.Window; win != nil {
		for p := int(win.Lo); p <= int(win.Hi) && p <= 0xFFFF; p++ {
			ap := netip.AddrPortFrom(win.IP.Unmap(), uint16(p))
			if ok, _ := w.admit(rt, ap, protocol.StagePredict); ok {
				out = append(out, extraTarget{to: ap, kind: candidate.KindTargets, window: true})
			} else {
				rejected++
			}
		}
	}
	rt.rejectTargets(w, rejected)
	return out, rejected
}

// followUp waits followUpDelay after a peer_seen; when the peer has still
// not been heard, the exact pair that got through sends three more punches
// (40 ms apart). They draw on the current round's grant, but running out of
// it cuts no planned stage short (no budget_hit). At most maxFollowUps run at
// once.
func (rt *runtime) followUp(fam protocol.Family, sockID uint8, target netip.AddrPort) {
	select {
	case rt.followUps <- struct{}{}:
	default:
		return
	}
	started := rt.pg.Go("followup:"+string(fam), func(ctx context.Context) {
		defer func() { <-rt.followUps }()
		if rt.sleep(ctx, followUpDelay) != nil || rt.punch.rx.Load() > 0 {
			return
		}
		s := rt.socks.byID(fam, sockID)
		run := rt.curRound.Load()
		if s == nil || run == nil {
			return
		}
		var meter *roundMeter
		for _, fr := range run.fams {
			if fr.w.fam == fam {
				meter = fr.meter
			}
		}
		if meter == nil {
			return
		}
		for i := range followUpPackets {
			if i > 0 && rt.sleep(ctx, followUpGap) != nil {
				return
			}
			h := udpwire.Header{Type: udpwire.TPunch, Round: run.plan.Round, Cand: extraStageIndex << 12}
			err := rt.sender.Send(ctx, s, target, &h, nil, sendOpt{class: classInitiate, stage: txDirect, round: meter, quota: quotaFollowUp})
			if err != nil && !errors.Is(err, errRun) { // a held-back punch is skipped: the next comes 40 ms later
				return
			}
		}
	})
	if !started {
		<-rt.followUps
	}
}
