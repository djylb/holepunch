package natprobe

import "sync/atomic"

// ServerStats are the server's counters.
// BytesOut ≤ BytesIn shows online that no reply outgrows its probe.
type ServerStats struct {
	PacketsIn, BytesIn, BytesOut uint64
	Short, Foreign, RateSource   uint64 // dropped before the route lookup
	UnknownRoute                 uint64 // unregistered, expired or closed route: never decrypted
	BadAuth, BadPayload          uint64 // AEAD failure; authentic but not a client probe
	BadObserver                  uint64 // aux observer id ≠ the listener's
	RateSession, Budget, Replay  uint64 // (session, role) rate, lifetime budget, replay window
	Acks, Extras, Alts           uint64 // replies sent
	Openers                      uint64 // authentic probes that came as an opener; their replies left as openers too
	SandwichEvents               uint64 // sandwich probes queued for the coordinator
	SandwichDropped              uint64 // sandwich queue full or closed
	Panics                       uint64 // recovered: per packet, reader loops, the sweeper, sinks
	WriteErrors, ReadErrors      uint64
	CloseTimeouts                uint64
	DeadListeners                int  // listeners stopped by a reader-loop panic
	WildcardMultiIP              bool // a wildcard group on a host with ≥ 2 global addresses of its family
}

// readerStats are one reader goroutine's counters: each reader writes only
// its own, so counting costs no shared cache line.
type readerStats struct {
	packetsIn, bytesIn, bytesOut            atomic.Uint64
	short, foreign, rateSrc, unknownRoute   atomic.Uint64
	badAuth, badPayload, badObserver        atomic.Uint64
	rateSession, budget, replay             atomic.Uint64
	acks, extras, alts, openers             atomic.Uint64
	sandwichEvents, sandwichDropped, panics atomic.Uint64
	writeErrs, readErrs                     atomic.Uint64
	_                                       [32]byte
}

// addTo adds r's counters to st.
func (r *readerStats) addTo(st *ServerStats) {
	st.PacketsIn += r.packetsIn.Load()
	st.BytesIn += r.bytesIn.Load()
	st.BytesOut += r.bytesOut.Load()
	st.Short += r.short.Load()
	st.Foreign += r.foreign.Load()
	st.RateSource += r.rateSrc.Load()
	st.UnknownRoute += r.unknownRoute.Load()
	st.BadAuth += r.badAuth.Load()
	st.BadPayload += r.badPayload.Load()
	st.BadObserver += r.badObserver.Load()
	st.RateSession += r.rateSession.Load()
	st.Budget += r.budget.Load()
	st.Replay += r.replay.Load()
	st.Acks += r.acks.Load()
	st.Extras += r.extras.Load()
	st.Alts += r.alts.Load()
	st.Openers += r.openers.Load()
	st.SandwichEvents += r.sandwichEvents.Load()
	st.SandwichDropped += r.sandwichDropped.Load()
	st.Panics += r.panics.Load()
	st.WriteErrors += r.writeErrs.Load()
	st.ReadErrors += r.readErrs.Load()
}
