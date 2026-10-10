package probe

import (
	crand "crypto/rand"
	"net/netip"
	"time"

	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/udpwire"
)

// want is the second reply a probe asks for.
type want uint8

const (
	wantNone want = iota
	wantExtra
	wantAlt
)

// targetKind is the role of a (socket, observer) target in the plan.
type targetKind uint8

const (
	kindMain    targetKind = iota // primary × main observer of the classification scope
	kindLAN                       // primary × main observer of another scope: a LAN hint, one send
	kindTopUp                     // primary × observer 0: the single extra WANT_EXTRA probe
	kindSecond                    // second socket × main observer
	kindSibling                   // sibling × observer 0
	kindAlt                       // primary × alt observer (solicited)
)

// target is one (socket, observer) the prober sends to.
type target struct {
	kind     targetKind
	sock     SocketHandle
	sockID   uint8
	obs      nat.Observer
	key      nat.PointKey
	want     want
	max      int // sends allowed
	sends    int
	last     time.Duration
	acked    bool
	observed netip.AddrPort // first answer
}

// probeRec is one sent probe, matched by its seq against the replies.
type probeRec struct {
	seq, ts uint32
	tg      *target
	at      time.Duration
	want    want
	acked   bool

	extraDeclared, extraSettled, extraSeen bool
	extraPort                              uint16
	extraDue                               time.Duration
	altDeclared, altSettled, altSeen       bool
	altDue                                 time.Duration
}

// stashed is an extra that arrived before the ack declaring it.
type stashed struct {
	seq  uint32
	from netip.AddrPort
	at   time.Duration
}

// stunTarget is one STUN server of the sub-probe.
type stunTarget struct {
	idx   uint8 // index in ProbeSpec.STUN (PointKey.Observer)
	addr  netip.AddrPort
	txid  [12]byte
	sends int
	last  time.Duration
	done  bool
}

// newRunState plans the probing: the main targets of the classification
// scope (global if any main observer is global, else private), the LAN hints,
// the WANT flags, the siblings and the STUN servers of the family.
func newRunState(p *Prober) *runState {
	s := &runState{
		p: p, codec: p.spec.Codec, table: p.table, t0: p.clk.Now(),
		deadline: clampDur(p.spec.Timeout, defaultTimeout, minTimeout, maxTimeout),
		rtt0:     defaultRTT, mappingDoneAt: -1, budget: serverBudget, stunBudget: stunBudget,
		buf: make([]byte, 0, udpwire.ProbeOuterSize+udpwire.MaxPlaintext+udpwire.TagSize),
	}
	if h := p.spec.Probe.RTTHintMs; h > 0 {
		s.rtt0 = min(time.Duration(h)*time.Millisecond, maxRTTHint)
	}
	if p.setupErr != "" {
		return s
	}
	scope := nat.ScopePrivate
	for _, o := range p.observers {
		if !o.Alt && o.Scope == nat.ScopeGlobal {
			scope = nat.ScopeGlobal
		}
	}
	for _, o := range p.observers {
		if o.Alt && o.Scope == scope {
			s.alts = append(s.alts, o)
		}
	}
	for _, o := range p.observers {
		if o.Alt {
			continue
		}
		tg := &target{sock: p.primary, sockID: p.primaryID, obs: o,
			key: nat.PointKey{Socket: p.primaryID, Source: nat.SourceServer, Observer: o.ID}}
		if o.Scope != scope {
			tg.kind, tg.max = kindLAN, 1
		} else {
			tg.kind, tg.max = kindMain, maxPrimarySends
			if s.obs0 == nil || o.ID < s.obs0.obs.ID {
				s.obs0 = tg
			}
			s.main = append(s.main, tg)
		}
		s.all = append(s.all, tg)
	}
	// The ExtraReply hint only saves bytes: without it no probe asks for an
	// extra the server would not send. What is sent is what the ack declares.
	for _, tg := range s.main {
		switch {
		case tg == s.obs0 && len(s.alts) > 0:
			tg.want = wantAlt
		case p.spec.Probe.ExtraReply:
			tg.want = wantExtra
		default:
			tg.want = wantNone
		}
	}
	if len(s.alts) == 0 || s.obs0 == nil {
		s.altPhase = altDone
	}
	if s.obs0 != nil {
		for _, sib := range p.siblings {
			s.all = append(s.all, &target{kind: kindSibling, sock: sib.h, sockID: sib.id, obs: s.obs0.obs, max: maxOtherSends,
				key: nat.PointKey{Socket: sib.id, Source: nat.SourceServer, Observer: s.obs0.obs.ID}})
		}
	}
	for i, a := range p.spec.Probe.STUN {
		a = unmap(a)
		if len(s.stun) == maxSTUNServers || a.Port() == 0 || !p.spec.Family.Matches(a.Addr()) || nat.ScopeOf(a.Addr()) == nat.ScopeNone {
			continue
		}
		st := &stunTarget{idx: uint8(i), addr: a}
		_, _ = crand.Read(st.txid[:]) // crypto/rand.Read never fails (Go 1.24+)
		s.stun = append(s.stun, st)
	}
	return s
}

// clampDur returns d, or def when d ≤ 0, clamped to [lo, hi].
func clampDur(d, def, lo, hi time.Duration) time.Duration {
	if d <= 0 {
		d = def
	}
	return min(max(d, lo), hi)
}
