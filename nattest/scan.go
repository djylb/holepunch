package nattest

import (
	"net/netip"
	"time"
)

// scanState implements ScanDefense for one NAT; it is guarded by NAT.mu.
// Thresholds of 0 are disabled (ScanDefense.normalized has applied the
// defaults).
type scanState struct {
	cfg     ScanDefense
	out     map[[2]netip.Addr]*scanTrack // (internal source IP, destination IP)
	unsol   map[netip.Addr]*countWindow  // remote source IP
	banInt  map[netip.Addr]time.Duration // internal IP -> banned until
	banExt  map[netip.Addr]time.Duration // remote IP -> banned until
	lastGC  time.Duration
	tracked bool // DistinctDstPorts or MaxConsecutiveRun is enabled
}

type scanTrack struct {
	ports *portWindow
	run   runState
	last  time.Duration
}

func newScanState(cfg ScanDefense) *scanState {
	return &scanState{
		cfg:     cfg,
		out:     make(map[[2]netip.Addr]*scanTrack),
		unsol:   make(map[netip.Addr]*countWindow),
		banInt:  make(map[netip.Addr]time.Duration),
		banExt:  make(map[netip.Addr]time.Duration),
		tracked: cfg.DistinctDstPorts > 0 || cfg.MaxConsecutiveRun > 0,
	}
}

// banned reports whether ip is banned at now, forgetting an expired ban.
func banned(m map[netip.Addr]time.Duration, ip netip.Addr, now time.Duration) bool {
	t, ok := m[ip]
	if !ok {
		return false
	}
	if now < t {
		return true
	}
	delete(m, ip)
	return false
}

func (s *scanState) bannedInternal(ip netip.Addr, now time.Duration) bool {
	return len(s.banInt) > 0 && banned(s.banInt, ip, now)
}

func (s *scanState) bannedExternal(ip netip.Addr, now time.Duration) bool {
	return len(s.banExt) > 0 && banned(s.banExt, ip, now)
}

// recordOut accounts an outbound packet and reports whether it triggered a
// new ban of its internal source IP.
func (s *scanState) recordOut(src netip.Addr, dst netip.AddrPort, now time.Duration) bool {
	s.gc(now)
	if !s.tracked {
		return false
	}
	key := [2]netip.Addr{src, dst.Addr()}
	tr := s.out[key]
	if tr == nil {
		tr = &scanTrack{ports: newPortWindow(s.cfg.Window)}
		s.out[key] = tr
	}
	tr.last = now
	distinct := tr.ports.add(now, dst.Port())
	run := tr.run.add(now, dst.Port(), s.cfg.Window)
	over := (s.cfg.DistinctDstPorts > 0 && distinct > s.cfg.DistinctDstPorts) ||
		(s.cfg.MaxConsecutiveRun > 0 && run > s.cfg.MaxConsecutiveRun)
	if !over || s.bannedInternal(src, now) {
		return false
	}
	s.banInt[src] = now + s.cfg.BanFor
	return true
}

// recordUnsolicited accounts a filtered inbound packet and reports whether
// it triggered a new ban of the remote IP that sent it.
func (s *scanState) recordUnsolicited(remote netip.Addr, now time.Duration) bool {
	if s.cfg.UnsolicitedInbound <= 0 {
		return false
	}
	w := s.unsol[remote]
	if w == nil {
		w = &countWindow{win: s.cfg.Window}
		s.unsol[remote] = w
	}
	if w.add(now) <= s.cfg.UnsolicitedInbound || s.bannedExternal(remote, now) {
		return false
	}
	s.banExt[remote] = now + s.cfg.BanFor
	return true
}

// gc forgets idle trackers once per Window, so that the state stays
// proportional to the recent traffic.
func (s *scanState) gc(now time.Duration) {
	if now-s.lastGC < s.cfg.Window {
		return
	}
	s.lastGC = now
	for k, tr := range s.out {
		if now-tr.last >= s.cfg.Window && tr.ports.idle(now) {
			delete(s.out, k)
		}
	}
	for k, w := range s.unsol {
		if w.count(now) == 0 {
			delete(s.unsol, k)
		}
	}
}
