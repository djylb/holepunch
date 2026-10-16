package candidate

import (
	"container/heap"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"time"

	"github.com/djylb/holepunch/protocol"
)

// A two-Manager simulation over a lossy, delaying, reordering, duplicating
// channel, stepped in fixed ticks. The initiator's upper layer sends its first
// datagram the moment it hands over and repeats it every upperPTO.

type simPath struct {
	iLoc, rAddr netip.AddrPort // initiator view
	rLoc, iAddr netip.AddrPort // responder view
	lossIR      float64        // extra loss I->R
	lossRI      float64        // extra loss R->I
	rttSample   time.Duration
	succAt      time.Duration // when both sides see their first success
	kindI       Kind
}

type simPkt struct {
	at     time.Time
	seq    int
	path   int
	epoch  uint16
	toInit bool
	kind   ActionKind
	upper  bool
}

type pktHeap []simPkt

func (h *pktHeap) Len() int { return len(*h) }
func (h *pktHeap) Less(i, j int) bool {
	s := *h
	if !s[i].at.Equal(s[j].at) {
		return s[i].at.Before(s[j].at)
	}
	return s[i].seq < s[j].seq
}
func (h *pktHeap) Swap(i, j int) { s := *h; s[i], s[j] = s[j], s[i] }
func (h *pktHeap) Push(x any)    { *h = append(*h, x.(simPkt)) }
func (h *pktHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}

type simCfg struct {
	loss     float64
	dup      float64
	oneWay   time.Duration
	jitter   time.Duration
	tickStep time.Duration
	horizon  time.Duration
	paths    []simPath
	upperPTO time.Duration
}

type simResult struct {
	iBy, rBy               protocol.HandoverEvidence
	log                    []string
	iPath, rPath           int
	iDoneAt, rDoneAt       time.Duration
	rConfirmAt             time.Duration
	iConfirms, rConfirms   int
	iHandovers, rHandovers int
	upperBeforeR           int // upper-layer datagrams R's library read before it handed over
	iEpoch, rEpoch         uint16
	iDone, rDone           bool
	iFail                  bool
	iPhase, rPhase         Phase
}

func runSim(cfg simCfg, rng *rand.Rand) simResult {
	base := time.Unix(1000, 0)
	init := NewManager(Config{Role: protocol.RoleInitiator})
	resp := NewManager(Config{Role: protocol.RoleResponder})
	var q pktHeap
	seq := 0
	res := simResult{iPath: -1, rPath: -1}
	logf := func(now time.Time, f string, a ...any) {
		res.log = append(res.log, fmt.Sprintf("%6dms ", now.Sub(base).Milliseconds())+fmt.Sprintf(f, a...))
	}
	pathOf := func(a Action, initiator bool) int {
		for j, p := range cfg.paths {
			if (initiator && p.iLoc == a.Local && p.rAddr == a.Remote) || (!initiator && p.rLoc == a.Local && p.iAddr == a.Remote) {
				return j
			}
		}
		panic(fmt.Sprintf("action on unknown pair %v->%v", a.Local, a.Remote))
	}
	send := func(now time.Time, toInit bool, path int, kind ActionKind, upper bool, e uint16) {
		extra := cfg.paths[path].lossIR
		if toInit {
			extra = cfg.paths[path].lossRI
		}
		copies := 1
		if rng.Float64() < cfg.dup {
			copies = 2
		}
		for range copies {
			if rng.Float64() < cfg.loss || rng.Float64() < extra {
				continue
			}
			d := cfg.oneWay
			if cfg.jitter > 0 {
				d += time.Duration(rng.Int64N(int64(cfg.jitter)))
			}
			seq++
			heap.Push(&q, simPkt{at: now.Add(d), seq: seq, toInit: toInit, path: path, kind: kind, upper: upper, epoch: e})
		}
	}
	var lastUpper time.Time
	handleI := func(now time.Time, acts []Action) {
		for _, a := range acts {
			switch a.Kind {
			case SendNominate, SendReady:
				logf(now, "I send %v e=%d path=%d", a.Kind, a.Epoch, pathOf(a, true))
				send(now, false, pathOf(a, true), a.Kind, false, a.Epoch)
			case Confirm:
				res.iConfirms++
			case HandOver:
				res.iHandovers++
				res.iDone, res.iPath, res.iEpoch, res.iBy, res.iDoneAt = true, pathOf(a, true), a.Epoch, a.ConfirmedBy, now.Sub(base)
				logf(now, "I handover e=%d by=%s", a.Epoch, a.ConfirmedBy)
				send(now, false, res.iPath, 0, true, 0)
				lastUpper = now
			case Fail:
				res.iFail = true
			default:
				panic(fmt.Sprintf("initiator emitted %v", a.Kind))
			}
		}
	}
	handleR := func(now time.Time, acts []Action) {
		for _, a := range acts {
			switch a.Kind {
			case SendAccept, SendAck:
				logf(now, "R send %v e=%d path=%d", a.Kind, a.Epoch, pathOf(a, false))
				send(now, true, pathOf(a, false), a.Kind, false, a.Epoch)
			case Confirm:
				res.rConfirms++
				res.rConfirmAt = now.Sub(base)
			case HandOver:
				res.rHandovers++
				res.rDone, res.rPath, res.rEpoch, res.rBy, res.rDoneAt = true, pathOf(a, false), a.Epoch, a.ConfirmedBy, now.Sub(base)
				logf(now, "R handover e=%d by=%s", a.Epoch, a.ConfirmedBy)
			case Fail:
			default:
				panic(fmt.Sprintf("responder emitted %v", a.Kind))
			}
		}
	}
	order := make([]int, len(cfg.paths))
	for j, p := range cfg.paths {
		order[j] = j
		if p.kindI != KindUnknown {
			init.Observe(base, p.iLoc, p.rAddr, protocol.FamilyUDP4, p.kindI)
		}
	}
	slices.SortStableFunc(order, func(a, b int) int { return int(cfg.paths[a].succAt - cfg.paths[b].succAt) })
	si := 0
	for t := time.Duration(0); t <= cfg.horizon; t += cfg.tickStep {
		now := base.Add(t)
		for si < len(order) && cfg.paths[order[si]].succAt <= t {
			p := cfg.paths[order[si]]
			init.Success(now, p.iLoc, p.rAddr, protocol.FamilyUDP4, p.rttSample)
			resp.Success(now, p.rLoc, p.iAddr, protocol.FamilyUDP4, p.rttSample)
			si++
		}
		for q.Len() > 0 && !q[0].at.After(now) {
			pk := heap.Pop(&q).(simPkt)
			p := cfg.paths[pk.path]
			if pk.toInit {
				if res.iDone {
					continue // the upper layer owns the socket
				}
				init.Touch(now, p.rAddr)
				switch {
				case pk.upper:
					handleI(now, init.RecvUpperLayer(now, netip.AddrPort{}, p.rAddr))
				case pk.kind == SendAccept:
					handleI(now, init.RecvAccept(now, pk.epoch, p.rAddr, 0))
				case pk.kind == SendAck:
					logf(now, "I recv ack e=%d", pk.epoch)
					handleI(now, init.RecvHandoverAck(now, pk.epoch, p.rAddr))
				}
				continue
			}
			if res.rDone {
				continue
			}
			resp.Touch(now, p.iAddr)
			switch {
			case pk.upper:
				res.upperBeforeR++
				logf(now, "R recv upper")
				handleR(now, resp.RecvUpperLayer(now, netip.AddrPort{}, p.iAddr))
			case pk.kind == SendNominate:
				handleR(now, resp.RecvNominate(now, pk.epoch, p.rLoc, p.iAddr, protocol.FamilyUDP4))
			case pk.kind == SendReady:
				handleR(now, resp.RecvReady(now, pk.epoch, p.iAddr, 0))
			}
		}
		if !res.iDone && !res.iFail {
			handleI(now, init.Tick(now))
		}
		if !res.rDone {
			handleR(now, resp.Tick(now))
		}
		if res.iDone && cfg.upperPTO > 0 && !res.rDone && now.Sub(lastUpper) >= cfg.upperPTO {
			send(now, false, res.iPath, 0, true, 0)
			lastUpper = now
		}
		if (res.iDone || res.iFail) && res.rDone {
			break
		}
	}
	res.iPhase, res.rPhase = init.Phase(), resp.Phase()
	return res
}

func twoPaths() []simPath {
	return []simPath{
		{iLoc: ap("192.0.2.1:5000"), rAddr: ap("203.0.113.9:40000"), rLoc: ap("198.51.100.5:6000"), iAddr: ap("203.0.113.1:50000"), rttSample: 100 * time.Millisecond, kindI: KindObserved},
		{iLoc: ap("192.0.2.1:5000"), rAddr: ap("203.0.113.9:40001"), rLoc: ap("198.51.100.5:6001"), iAddr: ap("203.0.113.1:50001"), rttSample: 100 * time.Millisecond, succAt: 20 * time.Millisecond, kindI: KindPredicted},
	}
}

func tail(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
