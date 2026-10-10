package protocol

import (
	"errors"
	"net/netip"
)

// testToken and testRoute are the values of the punch_start example.
var (
	testToken = mustToken("T3v1x0q5bJ8mH1YVt0rG2cN4cPq7Lw9yZr6sQ1eA2kM")
	testRoute = mustRoute("m9xZyQ2k1W0pS7aR3tU5vg")
)

func mustToken(s string) Token {
	var t Token
	if err := t.UnmarshalText([]byte(s)); err != nil {
		panic(err)
	}
	return t
}

func mustRoute(s string) RouteID {
	var r RouteID
	if err := r.UnmarshalText([]byte(s)); err != nil {
		panic(err)
	}
	return r
}

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

const testSession = "8Qm2s1Kc0b7ZtW9xPq3LrA"

func ptr[T any](v T) *T { return &v }

// isViolation reports whether err is a *ValidationError with reason
// protocol_violation.
func isViolation(err error) bool {
	var ve *ValidationError
	return errors.As(err, &ve) && ve.Reason == ReasonProtocolViolation
}

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func sampleTraits() Traits {
	return Traits{
		Family: FamilyUDP4, NoNAT: TriFalse, Mapping: MapAPDM, MappingConf: ConfHigh,
		Filtering: FiltPDF, FilteringConf: ConfMedium, PortAlloc: AllocSequential, PortAllocConf: ConfMedium,
		PortStep: -2, PortVelocity: 1.5, PortAnchor: 61003, PortAnchorMs: 123456, PortRangeLo: 61000, PortRangeHi: 62000,
		FirstPreserved: true, MultiExit: true, MultiHomed: true, Drifted: true, Hairpin: TriTrue, CGNAT: TriUnknown,
		CrossIP: true, PublicIP: ip("192.0.2.55"), Observed: ap("192.0.2.55:61001"), Samples: 3, Provisional: true,
	}
}

func sampleRoundPlan(round uint8) RoundPlan {
	return RoundPlan{
		Round: round, Variant: "pdf_recv_predict", Budget: BudgetBalanced, WindowMs: 2500, Final: true, Rescue: true,
		Seed: 2876543210,
		Sides: []FamilySide{{
			Family: FamilyUDP4, Role: SideReceiver, SendDelayMs: 80, Sockets: 2, MaxPackets: 200, MaxPPS: 120,
			MaxNewPerSec: 48, MaxDistinctPorts: 64, Sandwich: true,
			Stages: []Stage{
				{Kind: StageDirect, AtMs: 0, Targets: []netip.AddrPort{ap("192.0.2.55:61003"), ap("198.51.100.9:5")}, Repeats: 5, TTL: 4},
				{Kind: StagePredict, AtMs: 60, IP: ip("192.0.2.55"), Anchor: 61005, Steps: []int16{2, -1}, Span: 32, TTL: 4, Pair: true},
				{Kind: StageRandom, AtMs: 400, IP: ip("192.0.2.55"), Count: 128, Lo: 61000, Hi: 62000},
				{Kind: StageReplyOnly, AtMs: 900},
			},
		}},
	}
}

func samplePath(confirmedBy HandoverEvidence) *PathInfo {
	return &PathInfo{Family: FamilyUDP4, Local: ap("192.168.1.20:51820"), Remote: ap("192.0.2.55:61019"), Round: 2,
		Epoch: 1, Sock: 0, Cand: 8195, CandKind: CandTargets, Kind: PathPublic, RTTMs: 44, ConfirmedBy: confirmedBy}
}

// sampleMessages returns one fully populated, valid value of every message.
func sampleMessages() []Message {
	start := PunchStart{
		SessionID: testSession, Role: RoleInitiator,
		Token:   testToken,
		Wire:    WireSpec{RouteID: testRoute, PayloadMin: 93, PayloadMax: 271},
		Control: DefaultControlSpec(),
		Probe: ProbeSpec{V: ProbeSpecVersion, Observers: []ObserverSpec{{ID: 0, Addr: ap("203.0.113.7:3478")}, {ID: 1, Addr: ap("203.0.113.7:3479"), Group: 1, Alt: true}},
			ExtraReply: true, SecondSocket: true, Siblings: 2, STUN: []netip.AddrPort{ap("198.51.100.1:3478")}, RTTHintMs: 40},
		Timeouts: DefaultTimeouts(),
		Policy: &Policy{Budget: DefaultBudget(),
			PortMapping: PortMappingPolicy{EnableUPnP: ptr(true), EnablePCP: ptr(false), EnableNATPMP: ptr(true), LeaseSeconds: 3600},
			LowTTL:      ptr(true), LowTTLHops: []int{4, 7}},
	}
	report := ProbeReport{
		SessionID: testSession, Role: RoleInitiator, Control: DefaultControlSpec(),
		Caps:      ClientCaps{Impl: "holepunch-go/1.0.0", Families: []FamilyCaps{{Family: FamilyUDP4, LowTTL: true, RecvErr: true}}, MaxSockets: 40, PortMap: []PortMapMethod{PortMapPCP, PortMapUPnP}},
		ElapsedMs: 143,
		Families: []FamilyReport{{
			Family: FamilyUDP4, Failure: ReasonProbeTimeout,
			Sockets: []SocketReport{{ID: 0, Kind: SocketPrimary, Local: ap("192.168.1.20:51820"),
				Rows: []RowReport{{Observer: 0, Observed: ap("198.51.100.7:40123"), FirstSeq: 1, SentMs: 2, RTTMs: 31, Cookie: 2741901133}}}},
			Filters:    []FilterReport{{Socket: 0, Observer: 0, ExtraSeen: 1, AltSeen: 1}},
			STUN:       []RowReport{{Observer: 9, Observed: ap("198.51.100.7:40123"), FirstSeq: 7}},
			PortMap:    &PortMapReport{Method: PortMapPCP, External: netip.MustParseAddrPort("198.51.100.7:40000"), Internal: netip.MustParseAddrPort("192.168.1.20:51820"), LeaseSeconds: 7200},
			LocalAddrs: []netip.Addr{ip("192.168.1.20"), ip("10.0.0.8")},
			Traits:     sampleTraits(),
		}},
		Clock:     ClockSample{RTTMs: 30, OffsetMs: -412},
		Transport: Transport{Mode: "quic", Data: "c2hhMjU2OjQ1Njc4"},
	}
	summary := ProbeSummary{
		SessionID: testSession,
		Self:      PeerView{Families: []FamilyView{{Family: FamilyUDP4, Traits: sampleTraits(), Endpoints: []Endpoint{{Addr: ap("198.51.100.7:40123"), Source: EndpointServer, Socket: 0, Verified: true}}}}},
		Peer:      PeerView{Families: []FamilyView{{Family: FamilyUDP6, Traits: Traits{Family: FamilyUDP6, NoNAT: TriTrue}, Endpoints: []Endpoint{{Addr: ap("[2001:db8::2]:7000"), Source: EndpointLAN}}}}},
		Pair: PairFacts{SharedFamilies: []Family{FamilyUDP6, FamilyUDP4}, SamePublicIP: map[Family]bool{FamilyUDP4: true}, LikelySameLAN: map[Family]bool{FamilyUDP4: false},
			ProbeRTTMs: map[Role]uint32{RoleInitiator: 31, RoleResponder: 88}, ClockOffsetMs: map[Role]int64{RoleInitiator: -412}, Unverified: map[Family]bool{FamilyUDP4: true}},
		Transport: TransportPick{Mode: "quic", PeerData: "cGVlcg"},
		Timeouts:  DefaultTimeouts(),
		Plan: PlanSpec{ID: "p-7f3a", PairClass: "pdf_x_seq", RoundsMax: 5, Ladder: []string{"pdf_recv_predict", "swap_ttl"},
			Budget: Budget{MaxPackets: 2500, MaxPPS: 200, MaxDistinctTargets: 1024, MaxSockets: 8, MaxNewPerSec: 100, Birthday: BirthdayOff},
			Round1: sampleRoundPlan(1)},
	}
	ready := PunchReady{SessionID: testSession, Role: RoleResponder, ElapsedMs: 7, Families: []FamilyReady{{
		Family: FamilyUDP4, Sockets: 2, Clamped: true, Rejected: 3,
		PortMap: &PortMapReport{Method: PortMapUPnP, External: netip.MustParseAddrPort("198.51.100.7:40000"), Internal: netip.MustParseAddrPort("10.0.0.8:40002"), LeaseSeconds: 3600}}}}
	plan2 := sampleRoundPlan(2)
	gom := PunchGo{SessionID: testSession, Round: 2, DelayMs: 58, WindowMs: 2500, Final: true, RTTMs: 40, Plan: &plan2}
	progress := Progress{SessionID: testSession, Role: RoleInitiator, Seq: 1, Stage: "probe_done", Status: StatusOK, Round: 1, AtMs: 131,
		Detail: "done <ok>", Counters: map[string]uint32{"sent": 3}, Meta: map[string]string{"insecure": "1"}}
	seen := Assist{SessionID: testSession, Role: RoleResponder, Kind: AssistPeerSeen, Round: 1, Family: FamilyUDP4,
		Remote: ap("198.51.100.7:40123"), Local: ap("10.0.0.8:40002"), Sock: 1, Cand: 4097, Type: 7, First: true, Meta: map[string]string{"k": "v"}}
	relayed := seen.Relayed(RoleResponder)
	targets := Assist{SessionID: testSession, From: RoleServer, Kind: AssistPeerTargets, Round: 2, Family: FamilyUDP4,
		Targets: []netip.AddrPort{ap("192.0.2.55:61017")}, Window: &PortWindow{IP: ip("192.0.2.55"), Lo: 61017, Hi: 61019}, Source: TargetsSandwich}
	abort := Abort{SessionID: testSession, By: RoleServer, Code: ReasonServerBusy, Detail: "busy", RetryAfterMs: 5000}
	rr := RoundResult{SessionID: testSession, Role: RoleInitiator, Round: 2, ElapsedMs: 640, FireSkewMs: -3, Status: RoundConfirmed,
		Families: []FamilyOutcome{{Family: FamilyUDP4, Hit: true, SeenFrom: []netip.AddrPort{ap("192.0.2.55:61019")}, PeerSeenUs: true,
			Sent: 41, Recv: 6, DistinctPorts: 5, ICMPUnreach: 1, BindFailed: 1, BudgetHit: true, Drift: true, Rejected: 2,
			Remap: &Remap{Observer: 1, Observed: ap("198.51.100.9:40125"), Cookie: 0x5eed}}},
		Path: samplePath("")}
	pr := PunchResult{SessionID: testSession, Role: RoleResponder, OK: true, Code: ReasonInternal, Phase: PhaseDone, Detail: "ok",
		Path:   samplePath(ConfirmedByReady),
		Stats:  Stats{Sent: 211, Recv: 17, Replies: 9, Rounds: 2, Hits: 2, Drops: map[string]uint32{DropAuth: 1, DropReplay: 3}, BudgetHit: true},
		Timing: Timing{ProbeMs: 131, SummaryWaitMs: 930, GoWaitMs: 71, PunchMs: 3350, HandoverMs: 31},
		Traits: []TraitsUpdate{{Family: FamilyUDP4, Mapping: ptr(MapEIM), MappingConf: ptr(ConfHigh), Filtering: ptr(FiltADF),
			FilteringConf: ptr(ConfLow), PortStep: ptr(int16(2)), PortVelocity: ptr(float32(0.5)), Hairpin: ptr(TriFalse), Source: TraitsSourcePeer}},
		Warn: []string{WarnClockSkew}}
	return []Message{start, Ping{Seq: 1}, Pong{Seq: 1, HoldUs: 41, ClientUnixMs: 1791234567514}, report, summary, ready, gom,
		progress, seen, relayed, targets, abort, rr, pr}
}
