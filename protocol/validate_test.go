package protocol

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/djylb/holepunch/controlwire"
)

// sample returns a fresh copy of the sample message of type T.
func sample[T Message]() T {
	for _, m := range sampleMessages() {
		if v, ok := m.(T); ok {
			return v
		}
	}
	panic("no sample")
}

func repeat[T any](v T, n int) []T {
	out := make([]T, n)
	for i := range out {
		out[i] = v
	}
	return out
}

func observers(n int) []ObserverSpec {
	out := make([]ObserverSpec, n)
	for i := range out {
		out[i] = ObserverSpec{ID: uint8(i), Addr: netip.AddrPortFrom(ip("203.0.113.7"), uint16(3000+i))}
	}
	return out
}

func features(n int) []Feature {
	out := make([]Feature, n)
	for i := range out {
		out[i] = Feature(fmt.Sprintf("f%d", i))
	}
	return out
}

type vcase struct {
	name   string
	msg    Message
	ok     bool
	reason Reason // when !ok; default protocol_violation
	detail string // when !ok and set: the expected detail (field path)
}

func checkValidate(t *testing.T, cases []vcase) {
	t.Helper()
	for _, c := range cases {
		err := c.msg.Validate()
		if c.ok {
			if err != nil {
				t.Errorf("%s: Validate = %v, want ok", c.name, err)
			}
			continue
		}
		var verr *ValidationError
		if !errors.As(err, &verr) {
			t.Errorf("%s: Validate = %v, want a *ValidationError", c.name, err)
			continue
		}
		want := c.reason
		if want == "" {
			want = ReasonProtocolViolation
		}
		if verr.Reason != want || (c.detail != "" && verr.Detail != c.detail) {
			t.Errorf("%s: Validate = %v (reason %s detail %q), want %s %q", c.name, err, verr.Reason, verr.Detail, want, c.detail)
		}
	}
}

func TestValidateSamples(t *testing.T) {
	for _, m := range sampleMessages() {
		if err := m.Validate(); err != nil {
			t.Errorf("%s: %v", m.MessageType(), err)
		}
	}
}

func TestValidatePunchStart(t *testing.T) {
	with := func(f func(*PunchStart)) PunchStart { m := sample[PunchStart](); f(&m); return m }
	checkValidate(t, []vcase{
		{"session_64", with(func(m *PunchStart) { m.SessionID = strings.Repeat("a", 64) }), true, "", ""},
		{"start_background", with(func(m *PunchStart) { m.Mode = ModeBackground }), true, "", ""},
		{"start_mode_unknown", with(func(m *PunchStart) { m.Mode = "lazy" }), false, "", "mode"},
		{"session_65", with(func(m *PunchStart) { m.SessionID = strings.Repeat("a", 65) }), false, "", "session_id"},
		{"session_empty", with(func(m *PunchStart) { m.SessionID = "" }), false, "", "session_id"},
		{"session_charset", with(func(m *PunchStart) { m.SessionID = "a b" }), false, "", "session_id"},
		{"session_elided", with(func(m *PunchStart) { m.SessionID = "8Qm2…" }), false, "", "session_id"},
		{"role_server", with(func(m *PunchStart) { m.Role = RoleServer }), false, "", "role"},
		{"token_missing", with(func(m *PunchStart) { m.Token = Token{} }), false, "", "token"},
		{"route_missing", with(func(m *PunchStart) { m.Wire.RouteID = RouteID{} }), false, "", "wire.route_id"},
		{"control_version_below", with(func(m *PunchStart) { m.Control.Version = controlwire.Version - 1 }), false, ReasonControlVersionMismatch, "control.version"},
		{"control_version_above", with(func(m *PunchStart) { m.Control.Version = controlwire.Version + 1 }), false, ReasonControlVersionMismatch, "control.version"},
		{"features_16", with(func(m *PunchStart) { m.Control.Features = features(16) }), true, "", ""},
		{"features_17", with(func(m *PunchStart) { m.Control.Features = features(17) }), false, "", "control.features"},
		{"feature_unknown_ok", with(func(m *PunchStart) { m.Control.Features = []Feature{"future_thing"} }), true, "", ""},
		{"feature_syntax", with(func(m *PunchStart) { m.Control.Features = []Feature{"Sandwich"} }), false, "", "control.features[0]"},
		{"feature_32", with(func(m *PunchStart) { m.Control.Features = []Feature{Feature("a" + strings.Repeat("b", 31))} }), true, "", ""},
		{"feature_33", with(func(m *PunchStart) { m.Control.Features = []Feature{Feature("a" + strings.Repeat("b", 32))} }), false, "", "control.features[0]"},
		{"probe_v_below", with(func(m *PunchStart) { m.Probe.V = ProbeSpecVersion - 1 }), false, ReasonControlVersionMismatch, "probe_v"},
		{"probe_v_above", with(func(m *PunchStart) { m.Probe.V = ProbeSpecVersion + 1 }), false, ReasonControlVersionMismatch, "probe_v"},
		{"observers_0_is_no_probe_endpoint_not_a_violation", with(func(m *PunchStart) { m.Probe.Observers = nil }), true, "", ""},
		{"observers_16", with(func(m *PunchStart) { m.Probe.Observers = observers(16) }), true, "", ""},
		{"observers_17", with(func(m *PunchStart) { m.Probe.Observers = observers(17) }), false, "", "probe.observers"},
		{"observer_unspecified", with(func(m *PunchStart) { m.Probe.Observers[0].Addr = ap("0.0.0.0:3478") }), false, "", "probe.observers[0].addr"},
		{"observer_port0", with(func(m *PunchStart) { m.Probe.Observers[0].Addr = ap("203.0.113.7:0") }), false, "", "probe.observers[0].addr"},
		{"observer_4in6", with(func(m *PunchStart) { m.Probe.Observers[0].Addr = ap("[::ffff:203.0.113.7]:3478") }), false, "", "probe.observers[0].addr"},
		{"observer_v6", with(func(m *PunchStart) { m.Probe.Observers[0].Addr = ap("[2001:db8::7]:3478") }), true, "", ""},
		{"observer_dup_id", with(func(m *PunchStart) { m.Probe.Observers[1].ID = 0 }), false, "", "probe.observers[1].id"},
		{"siblings_9_clamped_not_rejected", with(func(m *PunchStart) { m.Probe.Siblings = 9 }), true, "", ""},
		{"stun_3", with(func(m *PunchStart) { m.Probe.STUN = repeat(ap("198.51.100.1:3478"), 3) }), false, "", "probe.stun"},
		{"policy_birthday", with(func(m *PunchStart) { m.Policy.Budget.Birthday = "huge" }), false, "", "policy.budget.birthday"},
		{"policy_hops_9", with(func(m *PunchStart) { m.Policy.LowTTLHops = repeat(4, 9) }), false, "", "policy.low_ttl_hops"},
		{"policy_nil", with(func(m *PunchStart) { m.Policy = nil }), true, "", ""},
		{"timeouts_out_of_range_clamped_not_rejected", with(func(m *PunchStart) { m.Timeouts.GoWaitMs = 1 }), true, "", ""},
	})
}

func TestValidatePingPong(t *testing.T) {
	checkValidate(t, []vcase{
		{"ping_0", Ping{Seq: 0}, false, "", "seq"},
		{"ping_8", Ping{Seq: 8}, true, "", ""},
		{"ping_9", Ping{Seq: 9}, false, "", "seq"},
		{"pong_0", Pong{}, false, "", "seq"},
		{"pong_8", Pong{Seq: 8, ClientUnixMs: -1}, true, "", ""},
	})
}

func TestValidateProbeReport(t *testing.T) {
	with := func(f func(*ProbeReport)) ProbeReport {
		m := sample[ProbeReport]()
		fam := m.Families[0]
		fam.Sockets = append([]SocketReport(nil), fam.Sockets...)
		m.Families = []FamilyReport{fam}
		f(&m)
		return m
	}
	sock := sample[ProbeReport]().Families[0].Sockets[0]
	row := sock.Rows[0]
	checkValidate(t, []vcase{
		{"role_missing", with(func(m *ProbeReport) { m.Role = "" }), false, "", "role"},
		{"report_background", with(func(m *ProbeReport) { m.Mode = ModeBackground }), true, "", ""},
		{"report_mode_unknown", with(func(m *ProbeReport) { m.Mode = "lazy" }), false, "", "mode"},
		{"families_0", with(func(m *ProbeReport) { m.Families = nil }), false, "", "families"},
		{"families_2", with(func(m *ProbeReport) {
			m.Families = append(m.Families, FamilyReport{Family: FamilyUDP6,
				Sockets: []SocketReport{{ID: 1 << 7, Kind: SocketPrimary, Local: ap("[2001:db8::20]:51820")}}})
		}), true, "", ""},
		{"families_dup", with(func(m *ProbeReport) { m.Families = append(m.Families, m.Families[0]) }), false, "", "families[1].family"},
		{"families_3", with(func(m *ProbeReport) { m.Families = repeat(m.Families[0], 3) }), false, "", "families"},
		{"sockets_6", with(func(m *ProbeReport) { m.Families[0].Sockets = repeat(sock, 6) }), true, "", ""},
		{"sockets_7", with(func(m *ProbeReport) { m.Families[0].Sockets = repeat(sock, 7) }), false, "", "families[0].sockets"},
		{"socket_kind", with(func(m *ProbeReport) { m.Families[0].Sockets[0].Kind = "birthday" }), false, "", "families[0].sockets[0].kind"},
		{"socket_local", with(func(m *ProbeReport) { m.Families[0].Sockets[0].Local = netip.AddrPort{} }), false, "", "families[0].sockets[0].local"},
		{"socket_local_family", with(func(m *ProbeReport) { m.Families[0].Sockets[0].Local = ap("[2001:db8::1]:5") }), false, "", "families[0].sockets[0].local"},
		{"rows_16", with(func(m *ProbeReport) { m.Families[0].Sockets[0].Rows = repeat(row, 16) }), true, "", ""},
		{"rows_17", with(func(m *ProbeReport) { m.Families[0].Sockets[0].Rows = repeat(row, 17) }), false, "", "families[0].sockets[0].rows"},
		{"row_observed_family", with(func(m *ProbeReport) { m.Families[0].Sockets[0].Rows = []RowReport{{Observed: ap("[2001:db8::1]:5")}} }), false, "", "families[0].sockets[0].rows[0].a"},
		{"row_observed_absent", with(func(m *ProbeReport) { m.Families[0].Sockets[0].Rows = []RowReport{{}} }), true, "", ""},
		{"filters_24", with(func(m *ProbeReport) { m.Families[0].Filters = make([]FilterReport, 24) }), true, "", ""},
		{"filters_25", with(func(m *ProbeReport) { m.Families[0].Filters = make([]FilterReport, 25) }), false, "", "families[0].filters"},
		{"stun_rows_5", with(func(m *ProbeReport) { m.Families[0].STUN = make([]RowReport, 5) }), false, "", "families[0].stun"},
		{"local_addrs_16", with(func(m *ProbeReport) { m.Families[0].LocalAddrs = repeat(ip("10.0.0.1"), 16) }), true, "", ""},
		{"local_addrs_17", with(func(m *ProbeReport) { m.Families[0].LocalAddrs = repeat(ip("10.0.0.1"), 17) }), false, "", "families[0].local_addrs"},
		{"local_addr_family", with(func(m *ProbeReport) { m.Families[0].LocalAddrs = []netip.Addr{ip("fe80::1")} }), false, "", "families[0].local_addrs[0]"},
		{"port_map_method", with(func(m *ProbeReport) { m.Families[0].PortMap = &PortMapReport{Method: "nat"} }), false, "", "families[0].port_map.method"},
		{"failure_code", with(func(m *ProbeReport) { m.Families[0].Failure = "Bad Code" }), false, "", "families[0].failure"},
		{"failure_unknown", with(func(m *ProbeReport) { m.Families[0].Failure = "probe_failed" }), false, "", "families[0].failure"},
		{"traits_family", with(func(m *ProbeReport) { m.Families[0].Traits.Family = FamilyUDP6 }), false, "", "families[0].traits.family"},
		{"traits_no_family_ok", with(func(m *ProbeReport) { m.Families[0].Traits.Family = "" }), true, "", ""},
		{"traits_public_ip_family", with(func(m *ProbeReport) { m.Families[0].Traits.PublicIP = ip("2001:db8::9") }), false, "", "families[0].traits.public_ip"},
		{"traits_enum", with(func(m *ProbeReport) { m.Families[0].Traits.Mapping = 7 }), false, "", "families[0].traits"},
		{"traits_range", with(func(m *ProbeReport) { m.Families[0].Traits.PortRangeLo = 9; m.Families[0].Traits.PortRangeHi = 8 }), false, "", "families[0].traits.port_lo"},
		{"caps_impl_64", with(func(m *ProbeReport) { m.Caps.Impl = strings.Repeat("x", 64) }), true, "", ""},
		{"caps_impl_65", with(func(m *ProbeReport) { m.Caps.Impl = strings.Repeat("x", 65) }), false, "", "caps.impl"},
		{"caps_port_map", with(func(m *ProbeReport) { m.Caps.PortMap = []PortMapMethod{"stun"} }), false, "", "caps.port_map[0]"},
		{"caps_families_3", with(func(m *ProbeReport) { m.Caps.Families = make([]FamilyCaps, 3) }), false, "", "caps.families"},
		{"transport_mode_16", with(func(m *ProbeReport) { m.Transport.Mode = strings.Repeat("q", 16) }), true, "", ""},
		{"transport_mode_17", with(func(m *ProbeReport) { m.Transport.Mode = strings.Repeat("q", 17) }), false, "", "transport.mode"},
		{"transport_data_8k", with(func(m *ProbeReport) { m.Transport.Data = strings.Repeat("d", 8<<10) }), true, "", ""},
		{"transport_data_8k1", with(func(m *ProbeReport) { m.Transport.Data = strings.Repeat("d", 8<<10+1) }), false, "", "transport"},
	})
}

func TestValidateSummaryAndPlans(t *testing.T) {
	with := func(f func(*ProbeSummary)) ProbeSummary {
		m := sample[ProbeSummary]()
		m.Plan.Round1 = sampleRoundPlan(1)
		f(&m)
		return m
	}
	ep := sample[ProbeSummary]().Self.Families[0].Endpoints[0]
	checkValidate(t, []vcase{
		{"endpoints_12", with(func(m *ProbeSummary) { m.Self.Families[0].Endpoints = repeat(ep, 12) }), true, "", ""},
		{"endpoints_13", with(func(m *ProbeSummary) { m.Self.Families[0].Endpoints = repeat(ep, 13) }), false, "", "self.families[0].endpoints"},
		{"endpoint_src", with(func(m *ProbeSummary) { m.Peer.Families[0].Endpoints[0].Source = "guess" }), false, "", "peer.families[0].endpoints[0].src"},
		{"endpoint_family", with(func(m *ProbeSummary) { m.Peer.Families[0].Endpoints[0].Addr = ap("192.0.2.1:5") }), false, "", "peer.families[0].endpoints[0].addr"},
		{"pair_family_key", with(func(m *ProbeSummary) { m.Pair.SamePublicIP = map[Family]bool{"ipx": true} }), false, "", "pair"},
		{"pair_role_key", with(func(m *ProbeSummary) { m.Pair.ProbeRTTMs = map[Role]uint32{RoleServer: 1} }), false, "", "pair.probe_rtt_ms"},
		{"shared_families_dup", with(func(m *ProbeSummary) { m.Pair.SharedFamilies = repeat(FamilyUDP4, 2) }), false, "", "pair.shared_families[1]"},
		{"view_families_3", with(func(m *ProbeSummary) { m.Self.Families = repeat(m.Self.Families[0], 3) }), false, "", "self.families"},
		{"shared_families_3", with(func(m *ProbeSummary) { m.Pair.SharedFamilies = repeat(FamilyUDP4, 3) }), false, "", "pair.shared_families"},
		{"peer_data_8k1", with(func(m *ProbeSummary) { m.Transport.PeerData = strings.Repeat("d", 8<<10+1) }), false, "", "transport"},
		{"rounds_max_0", with(func(m *ProbeSummary) { m.Plan.RoundsMax = 0 }), false, "", "plan.rounds_max"},
		{"rounds_max_9_clamped", with(func(m *ProbeSummary) { m.Plan.RoundsMax = 9 }), true, "", ""},
		{"plan_id_65", with(func(m *ProbeSummary) { m.Plan.ID = strings.Repeat("p", 65) }), false, "", "plan.id"},
		{"plan_id_missing", with(func(m *ProbeSummary) { m.Plan.ID = "" }), false, "", "plan.id"},
		{"variant_missing", with(func(m *ProbeSummary) { m.Plan.Round1.Variant = "" }), false, "", "plan.round1.variant"},
		{"window_0", with(func(m *ProbeSummary) { m.Plan.Round1.WindowMs = 0 }), false, "", "plan.round1.window_ms"},
		{"direct_no_targets", with(func(m *ProbeSummary) { m.Plan.Round1.Sides[0].Stages[0].Targets = nil }), false, "", "plan.round1.sides[0].stages[0].targets"},
		{"predict_no_steps", with(func(m *ProbeSummary) { m.Plan.Round1.Sides[0].Stages[1].Steps = nil }), false, "", "plan.round1.sides[0].stages[1].steps"},
		{"random_no_count", with(func(m *ProbeSummary) { m.Plan.Round1.Sides[0].Stages[2].Count = 0 }), false, "", "plan.round1.sides[0].stages[2].count"},
		{"stage_ip_family", with(func(m *ProbeSummary) { m.Plan.Round1.Sides[0].Stages[1].IP = ip("2001:db8::5") }), false, "", "plan.round1.sides[0].stages[1].ip"},
		{"target_family", with(func(m *ProbeSummary) { m.Plan.Round1.Sides[0].Stages[0].Targets[0] = ap("[2001:db8::5]:9") }), false, "", "plan.round1.sides[0].stages[0].targets[0]"},
		{"ladder_16", with(func(m *ProbeSummary) { m.Plan.Ladder = repeat("v", 16) }), true, "", ""},
		{"ladder_17", with(func(m *ProbeSummary) { m.Plan.Ladder = repeat("v", 17) }), false, "", "plan.ladder"},
		{"ladder_syntax", with(func(m *ProbeSummary) { m.Plan.Ladder = []string{"birthday light"} }), false, "", "plan.ladder[0]"},
		{"round1_is_2", with(func(m *ProbeSummary) { m.Plan.Round1.Round = 2 }), false, "", "plan.round1.round"},
		{"round_9", with(func(m *ProbeSummary) { m.Plan.Round1.Round = 9 }), false, "", "plan.round1.round"},
		{"class_unknown", with(func(m *ProbeSummary) { m.Plan.Round1.Budget = "medium" }), false, "", "plan.round1.budget"},
		{"sides_0", with(func(m *ProbeSummary) { m.Plan.Round1.Sides = nil }), false, "", "plan.round1.sides"},
		{"sides_3", with(func(m *ProbeSummary) { m.Plan.Round1.Sides = repeat(m.Plan.Round1.Sides[0], 3) }), false, "", "plan.round1.sides"},
		{"sides_dup", with(func(m *ProbeSummary) { m.Plan.Round1.Sides = repeat(m.Plan.Round1.Sides[0], 2) }), false, "", "plan.round1.sides[1].family"},
		{"side_role", with(func(m *ProbeSummary) { m.Plan.Round1.Sides[0].Role = "leader" }), false, "", "plan.round1.sides[0].role"},
		{"side_sockets_0", with(func(m *ProbeSummary) { m.Plan.Round1.Sides[0].Sockets = 0 }), false, "", "plan.round1.sides[0].sockets"},
		{"side_stages_0", with(func(m *ProbeSummary) { m.Plan.Round1.Sides[0].Stages = nil }), false, "", "plan.round1.sides[0].stages"},
		{"stage_kind", with(func(m *ProbeSummary) { m.Plan.Round1.Sides[0].Stages[0].Kind = "birthday" }), false, "", "plan.round1.sides[0].stages[0].kind"},
		{"predict_no_ip", with(func(m *ProbeSummary) { m.Plan.Round1.Sides[0].Stages[1].IP = netip.Addr{} }), false, "", "plan.round1.sides[0].stages[1].ip"},
		{"random_lo_gt_hi", with(func(m *ProbeSummary) { m.Plan.Round1.Sides[0].Stages[2].Lo = 62001 }), false, "", "plan.round1.sides[0].stages[2].lo"},
		{"predict_pair", with(func(m *ProbeSummary) { m.Plan.Round1.Sides[0].Stages[1].Pair = true }), true, "", ""},
		{"direct_pair", with(func(m *ProbeSummary) { m.Plan.Round1.Sides[0].Stages[0].Pair = true }), false, "", "plan.round1.sides[0].stages[0].pair"},
		{"random_pair", with(func(m *ProbeSummary) { m.Plan.Round1.Sides[0].Stages[2].Pair = true }), false, "", "plan.round1.sides[0].stages[2].pair"},
		// Fresh stages: targets or an IP, never both; one of each a side.
		{"fresh_targets", with(func(m *ProbeSummary) { m.Plan.Round1.Sides[0].Stages[3] = freshStage(ap("192.0.2.55:61003")) }), true, "", ""},
		{"fresh_ip", with(func(m *ProbeSummary) {
			m.Plan.Round1.Sides[0].Stages[3] = Stage{Kind: StageFresh, IP: ip("192.0.2.55"), Count: 4, Repeats: 2}
		}), true, "", ""},
		{"fresh_neither", with(func(m *ProbeSummary) { m.Plan.Round1.Sides[0].Stages[3] = Stage{Kind: StageFresh, Count: 4} }), false, "", "plan.round1.sides[0].stages[3].targets"},
		{"fresh_both", with(func(m *ProbeSummary) {
			m.Plan.Round1.Sides[0].Stages[3] = freshStage(ap("192.0.2.55:61003"))
			m.Plan.Round1.Sides[0].Stages[3].IP = ip("192.0.2.55")
		}), false, "", "plan.round1.sides[0].stages[3].targets"},
		{"fresh_count_0", with(func(m *ProbeSummary) {
			m.Plan.Round1.Sides[0].Stages[3] = freshStage(ap("192.0.2.55:61003"))
			m.Plan.Round1.Sides[0].Stages[3].Count = 0
		}), false, "", "plan.round1.sides[0].stages[3].count"},
		{"fresh_ip_family", with(func(m *ProbeSummary) {
			m.Plan.Round1.Sides[0].Stages[3] = Stage{Kind: StageFresh, IP: ip("2001:db8::1"), Count: 4}
		}), false, "", "plan.round1.sides[0].stages[3].ip"},
		{"fresh_twice", with(func(m *ProbeSummary) {
			m.Plan.Round1.Sides[0].Stages[2] = freshStage(ap("192.0.2.55:61003"))
			m.Plan.Round1.Sides[0].Stages[3] = freshStage(ap("192.0.2.55:61004"))
		}), false, "", "plan.round1.sides[0].stages"},
		{"plan_mode", with(func(m *ProbeSummary) { m.Plan.Mode, m.Plan.Advice = ModeBackground, AdviceBackgroundViable }), true, "", ""},
		{"plan_mode_unknown", with(func(m *ProbeSummary) { m.Plan.Mode = "lazy" }), false, "", "plan.mode"},
		{"plan_advice_unknown", with(func(m *ProbeSummary) { m.Plan.Advice = "retry" }), false, "", "plan.advice"},
		{"fresh_peer", with(func(m *ProbeSummary) {
			m.Plan.Round1.Sides[0].Stages[3] = Stage{Kind: StageFreshPeer, IP: ip("192.0.2.55"), Count: 8, Repeats: 3}
		}), true, "", ""},
		{"fresh_peer_no_ip", with(func(m *ProbeSummary) { m.Plan.Round1.Sides[0].Stages[3] = Stage{Kind: StageFreshPeer, Count: 8} }), false, "", "plan.round1.sides[0].stages[3].ip"},
		{"fresh_peer_targets", with(func(m *ProbeSummary) {
			m.Plan.Round1.Sides[0].Stages[3] = Stage{Kind: StageFreshPeer, IP: ip("192.0.2.55"), Count: 8, Targets: []netip.AddrPort{ap("192.0.2.55:1")}}
		}), false, "", "plan.round1.sides[0].stages[3].targets"},
		{"target_port_0", with(func(m *ProbeSummary) { m.Plan.Round1.Sides[0].Stages[0].Targets[0] = ap("192.0.2.1:0") }), false, "", "plan.round1.sides[0].stages[0].targets[0]"},
		{"d24_over_limits_clamped_not_rejected", with(func(m *ProbeSummary) {
			s := &m.Plan.Round1.Sides[0]
			s.Stages = repeat(s.Stages[3], 12)
			s.Stages[0] = Stage{Kind: StageDirect, Targets: repeat(ap("192.0.2.1:9"), 40), Repeats: 50, TTL: 1}
			s.MaxPPS, s.Sockets = 9000, 999
			m.Plan.Round1.WindowMs = 60000
		}), true, "", ""},
	})
}

func TestValidatePunchGo(t *testing.T) {
	with := func(f func(*PunchGo)) PunchGo {
		m := sample[PunchGo]()
		p := sampleRoundPlan(2)
		m.Plan = &p
		f(&m)
		return m
	}
	checkValidate(t, []vcase{
		{"round_0", with(func(m *PunchGo) { m.Round = 0 }), false, "", "round"},
		{"round_9", with(func(m *PunchGo) { m.Round = 9; m.Plan.Round = 9 }), false, "", "round"},
		{"round_8", with(func(m *PunchGo) { m.Round = 8; m.Plan.Round = 8 }), true, "", ""},
		{"round1_without_plan", with(func(m *PunchGo) { m.Round = 1; m.Plan = nil }), true, "", ""},
		// Round 1's plan is the summary's; a go may carry it again as
		// an anchor update, valid as any plan, which the client
		// checks against the summary's (CheckAnchorUpdate).
		{"round1_with_plan", with(func(m *PunchGo) { m.Round = 1; m.Plan.Round = 1 }), true, "", ""},
		{"round1_with_bad_plan", with(func(m *PunchGo) { m.Round = 1; m.Plan.Round = 1; m.Plan.Variant = "" }), false, "", "plan.variant"},
		{"round1_plan_of_round_2", with(func(m *PunchGo) { m.Round = 1 }), false, "", "plan.round"},
		{"round2_without_plan", with(func(m *PunchGo) { m.Plan = nil }), false, "", "plan"},
		{"plan_round_mismatch", with(func(m *PunchGo) { m.Plan.Round = 3 }), false, "", "plan.round"},
		{"window_mismatch", with(func(m *PunchGo) { m.WindowMs = 100 }), false, "", "window"}, // a go repeats its plan's window
		{"delay_over_clamped_not_rejected", with(func(m *PunchGo) { m.DelayMs = 60000 }), true, "", ""},
	})
}

func TestValidateClientMessages(t *testing.T) {
	ready := func(f func(*PunchReady)) PunchReady { m := sample[PunchReady](); f(&m); return m }
	prog := func(f func(*Progress)) Progress { m := sample[Progress](); f(&m); return m }
	checkValidate(t, []vcase{
		{"ready_families_0", ready(func(m *PunchReady) { m.Families = nil }), false, "", "families"},
		{"ready_families_3", ready(func(m *PunchReady) { m.Families = repeat(m.Families[0], 3) }), false, "", "families"},
		{"ready_sockets_0", ready(func(m *PunchReady) { m.Families[0].Sockets = 0 }), false, "", "families[0].sockets"},
		{"ready_port_map", ready(func(m *PunchReady) {
			m.Families[0].PortMap = &PortMapReport{Method: PortMapUPnP, External: netip.AddrPortFrom(netip.MustParseAddr("198.51.100.7"), 0)}
		}), false, "", "families[0].port_map.external"},
		{"progress_stage_empty", prog(func(m *Progress) { m.Stage = "" }), false, "", "stage"},
		{"progress_stage_unknown_ok", prog(func(m *Progress) { m.Stage = "future_stage_2" }), true, "", ""},
		{"progress_stage_case", prog(func(m *Progress) { m.Stage = "Fire" }), false, "", "stage"},
		{"progress_status", prog(func(m *Progress) { m.Status = "warn" }), false, "", "status"},
		{"progress_round_9", prog(func(m *Progress) { m.Round = 9 }), false, "", "round"},
		{"progress_detail_128", prog(func(m *Progress) { m.Detail = strings.Repeat("d", 128) }), true, "", ""},
		{"progress_detail_129", prog(func(m *Progress) { m.Detail = strings.Repeat("d", 129) }), false, "", "detail"},
		{"progress_meta_64", prog(func(m *Progress) { m.Meta = map[string]string{"k": strings.Repeat("v", 64)} }), true, "", ""},
		{"progress_meta_65", prog(func(m *Progress) { m.Meta = map[string]string{"k": strings.Repeat("v", 65)} }), false, "", "meta.k"},
		{"progress_meta_17_keys_truncated_not_rejected", prog(func(m *Progress) {
			m.Meta = map[string]string{}
			for i := 0; i < 17; i++ {
				m.Meta[fmt.Sprint(i)] = "v"
			}
		}), true, "", ""},
	})
}

func TestValidateAssistAbort(t *testing.T) {
	seen := func(f func(*Assist)) Assist { m := sample[Assist](); f(&m); return m }
	abort := func(f func(*Abort)) Abort { m := sample[Abort](); f(&m); return m }
	checkValidate(t, []vcase{
		{"unknown_kind_minimal", Assist{SessionID: testSession, Kind: "future_kind"}, true, "", ""},
		{"kind_empty", seen(func(m *Assist) { m.Kind = "" }), false, "", "kind"},
		{"role_server", seen(func(m *Assist) { m.Role = RoleServer }), false, "", "role"},
		{"seen_round_0", seen(func(m *Assist) { m.Round = 0 }), false, "", "round"},
		{"seen_family", seen(func(m *Assist) { m.Family = "" }), false, "", "family"},
		{"seen_remote_missing", seen(func(m *Assist) { m.Remote = netip.AddrPort{} }), false, "", "remote"},
		{"seen_remote_family", seen(func(m *Assist) { m.Remote = ap("[2001:db8::1]:9") }), false, "", "remote"},
		{"seen_local_port0", seen(func(m *Assist) { m.Local = ap("10.0.0.8:0") }), false, "", "local"},
		{"meta_8_ok", seen(func(m *Assist) { m.Meta = map[string]string{"a": "b"} }), true, "", ""},
		// Server-only fields sent by a client are not a violation: the server
		// drops them.
		{"client_from_dropped_not_rejected", seen(func(m *Assist) { m.From = "bogus" }), true, "", ""},
		{"client_targets_dropped_not_rejected", seen(func(m *Assist) {
			m.Kind, m.Targets, m.Source = AssistPeerTargets, []netip.AddrPort{{}}, "x"
		}), true, "", ""},
		{"abort_by", abort(func(m *Abort) { m.By = "" }), false, "", "by"},
		{"abort_code_empty_ok", abort(func(m *Abort) { m.Code = "" }), true, "", ""},
		{"abort_code_unknown_ok", abort(func(m *Abort) { m.Code = "future_code" }), true, "", ""},
		{"abort_code_syntax", abort(func(m *Abort) { m.Code = "Server Busy" }), false, "", "code"},
		{"abort_detail_256", abort(func(m *Abort) { m.Detail = strings.Repeat("d", 256) }), true, "", ""},
		{"abort_detail_257", abort(func(m *Abort) { m.Detail = strings.Repeat("d", 257) }), false, "", "detail"},
	})
}

// TestAssistDirections: server-written fields are checked where they are
// consumed (ValidateRelayed, on the client), stripped where they are not
// (StripServerFields, on the server), and Relayed builds the forwarded form.
func TestAssistDirections(t *testing.T) {
	var targets Assist
	for _, x := range sampleMessages() {
		if a, ok := x.(Assist); ok && a.Kind == AssistPeerTargets {
			targets = a
		}
	}
	withTargets := func(f func(*Assist)) Assist {
		m := targets
		w := *m.Window
		m.Window = &w
		f(&m)
		return m
	}
	relayed := func(name string, m Assist, ok bool, detail string) {
		t.Helper()
		err := m.ValidateRelayed()
		var verr *ValidationError
		switch {
		case ok && err != nil:
			t.Errorf("%s: ValidateRelayed = %v", name, err)
		case !ok && (!errors.As(err, &verr) || verr.Detail != detail):
			t.Errorf("%s: ValidateRelayed = %v, want detail %q", name, err, detail)
		}
	}
	relayed("targets_ok", targets, true, "")
	relayed("targets_source", withTargets(func(m *Assist) { m.Source = "" }), false, "source")
	relayed("targets_from_peer", withTargets(func(m *Assist) { m.From = RoleInitiator }), false, "from")
	relayed("targets_window_inverted", withTargets(func(m *Assist) { m.Window.Lo, m.Window.Hi = 9, 8 }), false, "window")
	relayed("targets_window_ip", withTargets(func(m *Assist) { m.Window.IP = netip.Addr{} }), false, "window.ip")
	relayed("targets_bad", withTargets(func(m *Assist) { m.Targets = []netip.AddrPort{{}} }), false, "targets[0]")
	relayed("targets_empty", withTargets(func(m *Assist) { m.Targets, m.Window = nil, nil }), false, "targets")
	relayed("targets_window_only", withTargets(func(m *Assist) { m.Targets = nil }), true, "")
	refresh := Assist{SessionID: testSession, From: RoleServer, Kind: AssistRefresh, Round: 2, Family: FamilyUDP4}
	if err := refresh.Validate(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	relayed("refresh_ok", refresh, true, "")
	relayed("refresh_from_peer", func() Assist { m := refresh; m.From = RoleResponder; return m }(), false, "from")
	if bad := (Assist{SessionID: testSession, Kind: AssistRefresh, Family: FamilyUDP4}); bad.Validate() == nil {
		t.Fatal("refresh without a round")
	}
	relayed("targets_window_wide_clamped_not_rejected", withTargets(func(m *Assist) { m.Window.Hi = m.Window.Lo + 500 }), true, "")

	seen := sample[Assist]()
	relayed("seen_from_missing", seen, false, "from")
	relayed("seen_from_server", func() Assist { m := seen; m.From = RoleServer; return m }(), false, "from")
	fwd := seen.Relayed(RoleResponder)
	relayed("seen_relayed", fwd, true, "")
	if fwd.Role != "" || fwd.Local.IsValid() || fwd.From != RoleResponder || fwd.Remote != seen.Remote || fwd.Cand != seen.Cand {
		t.Fatalf("Relayed = %+v", fwd)
	}
	if err := CheckOrigin(fwd, testSession, ""); err != nil {
		t.Fatalf("relayed assist origin: %v", err)
	}

	forged := seen
	forged.From, forged.Targets, forged.Window, forged.Source = RoleServer, []netip.AddrPort{ap("203.0.113.66:1")}, &PortWindow{}, TargetsInject
	stripped, had := forged.StripServerFields()
	if !had || stripped.From != "" || stripped.Targets != nil || stripped.Window != nil || stripped.Source != "" {
		t.Fatalf("StripServerFields left %+v", stripped)
	}
	if forged.From != RoleServer || forged.Window == nil {
		t.Fatal("StripServerFields wrote its receiver")
	}
	if _, had := stripped.StripServerFields(); had {
		t.Fatal("second StripServerFields reported fields")
	}
	// A forged frame reaches the peer without the forged fields.
	f, err := Marshal(func() Assist {
		m := seen
		m.From, m.Targets = RoleServer, []netip.AddrPort{ap("203.0.113.66:1")}
		return m
	}().Relayed(RoleInitiator))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(f.Payload), "203.0.113.66") || strings.Contains(string(f.Payload), `"local"`) {
		t.Fatalf("forwarded frame carries forged or local fields: %s", f.Payload)
	}
	// Marshal refuses what the sender may not write.
	if _, err := Marshal(withTargets(func(m *Assist) { m.Source = "" })); !isViolation(err) {
		t.Fatalf("Marshal(invalid server assist) = %v", err)
	}
	if _, err := Marshal(func() Assist { m := seen; m.Source = TargetsInject; return m }()); !isViolation(err) {
		t.Fatalf("Marshal(client assist with server fields) = %v", err)
	}
}

// TestMetaLimits: meta holds at most 1 KiB in all.
func TestMetaLimits(t *testing.T) {
	p := sample[Progress]()
	p.Meta = map[string]string{}
	for i := 0; i < 12; i++ {
		p.Meta[fmt.Sprintf("key%02d", i)] = strings.Repeat("v", 64) // 12 × 69 B = 828 B
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("828 B meta: %v", err)
	}
	for i := 12; i < 16; i++ {
		p.Meta[fmt.Sprintf("key%02d", i)] = strings.Repeat("v", 64) // 16 × 69 B = 1104 B
	}
	var verr *ValidationError
	if err := p.Validate(); !errors.As(err, &verr) || verr.Detail != "meta" {
		t.Fatalf("1104 B meta: %v", err)
	}
	// Keys beyond the 16 kept by Normalize do not count.
	p.Meta = map[string]string{}
	for i := 0; i < 16; i++ {
		p.Meta[fmt.Sprintf("key%02d", i)] = strings.Repeat("v", 57) // 16 × 62 B = 992 B kept
	}
	p.Meta["zzz_dropped_by_normalize_1"] = strings.Repeat("v", 64)
	p.Meta["zzz_dropped_by_normalize_2"] = strings.Repeat("v", 64)
	if err := p.Validate(); err != nil {
		t.Fatalf("meta whose kept keys fit: %v", err)
	}
	a := sample[Assist]()
	a.Meta = map[string]string{}
	for i := 0; i < 8; i++ {
		a.Meta[fmt.Sprintf("k%d", i)] = strings.Repeat("v", 64)
	}
	if err := a.Validate(); err != nil {
		t.Fatalf("assist meta: %v", err)
	}
}

func TestValidateResults(t *testing.T) {
	rr := func(f func(*RoundResult)) RoundResult {
		m := sample[RoundResult]()
		m.Families = append([]FamilyOutcome(nil), m.Families...)
		f(&m)
		return m
	}
	pr := func(f func(*PunchResult)) PunchResult { m := sample[PunchResult](); f(&m); return m }
	tu := sample[PunchResult]().Traits[0]
	checkValidate(t, []vcase{
		{"rr_status", rr(func(m *RoundResult) { m.Status = "done" }), false, "", "status"},
		{"rr_fatal_without_code", rr(func(m *RoundResult) { m.Status = RoundFatal; m.Code = "" }), false, "", "code"},
		{"rr_fatal", rr(func(m *RoundResult) { m.Status = RoundFatal; m.Code = ReasonUDPBlocked; m.Path = nil }), true, "", ""},
		{"rr_confirmed_without_path", rr(func(m *RoundResult) { m.Path = nil }), false, "", "path"},
		{"rr_window_end", rr(func(m *RoundResult) { m.Status = RoundWindowEnd; m.Path = nil }), true, "", ""},
		{"rr_families_3", rr(func(m *RoundResult) { m.Families = repeat(m.Families[0], 3) }), false, "", "families"},
		{"rr_seen_from_4", rr(func(m *RoundResult) { m.Families[0].SeenFrom = repeat(ap("192.0.2.1:9"), 4) }), true, "", ""},
		{"rr_seen_from_5", rr(func(m *RoundResult) { m.Families[0].SeenFrom = repeat(ap("192.0.2.1:9"), 5) }), false, "", "families[0].seen_from"},
		{"rr_remap_family", rr(func(m *RoundResult) { m.Families[0].Remap = &Remap{Observed: ap("[2001:db8::1]:9"), Cookie: 1} }), false, "", "families[0].remap.a"},
		{"rr_remap_port", rr(func(m *RoundResult) { m.Families[0].Remap = &Remap{Observed: ap("192.0.2.1:0"), Cookie: 1} }), false, "", "families[0].remap.a"},
		{"rr_remap_cookie", rr(func(m *RoundResult) { m.Families[0].Remap = &Remap{Observed: ap("192.0.2.1:9")} }), false, "", "families[0].remap.c"},
		{"rr_remap", rr(func(m *RoundResult) {
			m.Families[0].Remap = &Remap{Observer: 2, Observed: ap("192.0.2.1:9"), Cookie: 7}
		}), true, "", ""},
		{"rr_path_kind", rr(func(m *RoundResult) { p := *m.Path; p.CandKind = "magic"; m.Path = &p }), false, "", "path.cand_kind"},
		{"rr_path_kind_portmap", rr(func(m *RoundResult) { p := *m.Path; p.CandKind = "portmap"; m.Path = &p }), false, "", "path.cand_kind"}, // a confirmed path is never a portmap kind
		{"rr_path_round", rr(func(m *RoundResult) { p := *m.Path; p.Round = 0; m.Path = &p }), false, "", "path.round"},
		{"pr_ok_without_path", pr(func(m *PunchResult) { m.Path = nil }), false, "", "path"},
		{"pr_ok_without_evidence", pr(func(m *PunchResult) { m.Path = samplePath("") }), false, "", "path.confirmed_by"},
		{"pr_evidence_unknown", pr(func(m *PunchResult) { m.Path = samplePath("magic") }), false, "", "path.confirmed_by"},
		{"pr_path_kind_portmap", pr(func(m *PunchResult) { m.Path = samplePath(ConfirmedByAck); m.Path.CandKind = "portmap" }), false, "", "path.cand_kind"}, // a confirmed path is never a portmap kind
		{"pr_fail_without_code", pr(func(m *PunchResult) { m.OK = false; m.Code = "" }), false, "", "code"},
		{"pr_extra_paths", pr(func(m *PunchResult) { m.ExtraPaths = repeat(*samplePath(ConfirmedByAck), MaxPaths-1) }), true, "", ""}, // the most extra paths
		{"pr_extra_paths_8", pr(func(m *PunchResult) { m.ExtraPaths = repeat(*samplePath(ConfirmedByAck), MaxPaths) }), false, "", "extra_paths"},
		{"pr_extra_paths_failed", pr(func(m *PunchResult) {
			m.OK, m.Code, m.Path, m.Phase = false, ReasonProbeTimeout, nil, PhaseFailed
			m.ExtraPaths = []PathInfo{*samplePath(ConfirmedByAck)}
		}), false, "", "extra_paths"},
		{"pr_extra_path_without_evidence", pr(func(m *PunchResult) { m.ExtraPaths = []PathInfo{*samplePath("")} }), false, "", "extra_paths[0].confirmed_by"},
		{"pr_extra_path_kind", pr(func(m *PunchResult) {
			p := *samplePath(ConfirmedByAck)
			p.Kind = "tunnel"
			m.ExtraPaths = []PathInfo{p}
		}), false, "", "extra_paths[0].kind"},
		{"pr_fail", pr(func(m *PunchResult) { m.OK, m.Code, m.Path, m.Phase = false, ReasonProbeTimeout, nil, PhaseFailed }), true, "", ""},
		{"pr_phase", pr(func(m *PunchResult) { m.Phase = "finished" }), false, "", "phase"},
		{"pr_detail_257", pr(func(m *PunchResult) { m.Detail = strings.Repeat("d", 257) }), false, "", "detail"},
		{"pr_traits_2", pr(func(m *PunchResult) { v6 := tu; v6.Family = FamilyUDP6; m.Traits = []TraitsUpdate{tu, v6} }), true, "", ""},
		{"pr_traits_dup", pr(func(m *PunchResult) { m.Traits = repeat(tu, 2) }), false, "", "traits[1].family"},
		{"pr_code_unknown", pr(func(m *PunchResult) { m.OK, m.Code, m.Phase = false, "probe_failed", PhaseFailed }), false, "", "code"},
		{"pr_velocity_nan", pr(func(m *PunchResult) { u := tu; u.PortVelocity = ptr(float32(math.NaN())); m.Traits = []TraitsUpdate{u} }), false, "", "traits[0].port_velocity"},
		{"pr_traits_3", pr(func(m *PunchResult) { m.Traits = repeat(tu, 3) }), false, "", "traits"},
		{"pr_traits_source", pr(func(m *PunchResult) { u := tu; u.Source = "guess"; m.Traits = []TraitsUpdate{u} }), false, "", "traits[0].source"},
		{"pr_traits_enum", pr(func(m *PunchResult) { u := tu; u.Hairpin = ptr(Tri(5)); m.Traits = []TraitsUpdate{u} }), false, "", "traits[0]"},
		{"pr_warn_8", pr(func(m *PunchResult) { m.Warn = repeat(WarnClockSkew, 8) }), true, "", ""},
		{"pr_warn_9", pr(func(m *PunchResult) { m.Warn = repeat(WarnClockSkew, 9) }), false, "", "warn"},
		{"pr_warn_unknown_ok", pr(func(m *PunchResult) { m.Warn = []string{"future_warning"} }), true, "", ""},
		{"pr_warn_syntax", pr(func(m *PunchResult) { m.Warn = []string{"Clock Skew"} }), false, "", "warn[0]"},
	})
}

// TestNormalizeClamps covers the receiver-side clamps and idempotence.
func TestNormalizeClamps(t *testing.T) {
	p := sampleRoundPlan(2)
	p.Budget = BudgetLight
	p.WindowMs = 60000
	s := &p.Sides[0]
	s.SendDelayMs, s.Sockets, s.MaxPackets, s.MaxPPS, s.MaxNewPerSec, s.MaxDistinctPorts = 9000, 999, 1e6, 9000, 9000, 9000
	s.Stages = append(s.Stages, repeat(Stage{Kind: StageReplyOnly}, 8)...)
	s.Stages[0].Targets = repeat(ap("192.0.2.1:9"), 40)
	s.Stages[0].Repeats, s.Stages[0].TTL = 50, 1
	s.Stages[1].Steps, s.Stages[1].Span, s.Stages[1].TTL = []int16{1, 2, 3, 4, 5}, 60000, 200
	s.Stages[2].Count = 60000
	in := PunchGo{SessionID: testSession, Round: 2, DelayMs: 60000, WindowMs: 60000, Plan: &p}
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
	original := clonePunchGo(in)
	g, clamped := in.Normalize()
	if !clamped {
		t.Fatal("Normalize reported no clamp")
	}
	if !reflect.DeepEqual(original, in) {
		t.Fatal("Normalize wrote its receiver")
	}
	s = &g.Plan.Sides[0]
	light, _ := BudgetLight.Limits()
	type limits struct {
		delay, window, sendDelay, sockets uint16
		packets                           uint32
		pps, newPerSec, ports             uint16
		stages, targets, steps            int
		repeats, ttl0, ttl1               uint8
		span, count                       uint16
	}
	want := limits{2000, 10000, 3000, light.MaxSockets, light.MaxPackets, light.MaxPPS, 256, light.MaxDistinctPorts, 8, 16, 3, 8, 2, 64, 4096, 4096}
	got := limits{
		delay: g.DelayMs, window: g.Plan.WindowMs, sendDelay: s.SendDelayMs, sockets: s.Sockets,
		packets: s.MaxPackets, pps: s.MaxPPS, newPerSec: s.MaxNewPerSec, ports: s.MaxDistinctPorts,
		stages: len(s.Stages), targets: len(s.Stages[0].Targets), steps: len(s.Stages[1].Steps),
		repeats: s.Stages[0].Repeats, ttl0: s.Stages[0].TTL, ttl1: s.Stages[1].TTL, span: s.Stages[1].Span, count: s.Stages[2].Count,
	}
	if got != want {
		t.Fatalf("after Normalize %+v\nwant %+v", got, want)
	}
	if again, clamped := g.Normalize(); clamped || !reflect.DeepEqual(again, g) {
		t.Fatal("Normalize is not idempotent")
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("Validate after Normalize: %v", err)
	}
}

// clonePunchGo copies g deeply enough to see any write to its plan.
func clonePunchGo(g PunchGo) PunchGo {
	p := *g.Plan
	p.Sides = append([]FamilySide(nil), p.Sides...)
	for i, s := range p.Sides {
		s.Stages = append([]Stage(nil), s.Stages...)
		for j, st := range s.Stages {
			st.Targets = append([]netip.AddrPort(nil), st.Targets...)
			st.Steps = append([]int16(nil), st.Steps...)
			s.Stages[j] = st
		}
		p.Sides[i] = s
	}
	g.Plan = &p
	return g
}

func TestNormalizeOtherMessages(t *testing.T) {
	start := sample[PunchStart]()
	start.Wire.PayloadMin, start.Wire.PayloadMax = 10, 5000
	start.Timeouts = Timeouts{GoWaitMs: 1}
	start.Probe.Siblings = 9
	start.Policy.Budget.MaxPackets = 1 << 30
	start.Policy.LowTTLHops = []int{1, 4, 4, 99}
	policy := *start.Policy
	start, clamped := start.Normalize()
	if !clamped {
		t.Fatal("no clamp reported")
	}
	if start.Policy.Budget.MaxPackets == policy.Budget.MaxPackets {
		t.Fatal("Normalize wrote the policy it was given")
	}
	if start.Wire.PayloadMin != 48 || start.Wire.PayloadMax != 1024 || start.Timeouts.GoWaitMs != 500 || start.Timeouts.MaxRounds != 5 ||
		start.Probe.Siblings != 2 || start.Policy.Budget.MaxPackets != 40000 || !reflect.DeepEqual(start.Policy.LowTTLHops, []int{2, 4, 32}) {
		t.Fatalf("PunchStart after Normalize: wire %+v timeouts %+v siblings %d budget %+v hops %v",
			start.Wire, start.Timeouts, start.Probe.Siblings, start.Policy.Budget, start.Policy.LowTTLHops)
	}
	if _, clamped := start.Normalize(); clamped {
		t.Fatal("PunchStart.Normalize not idempotent")
	}
	defaults := sample[PunchStart]()
	defaults.Timeouts = Timeouts{}
	if defaults, clamped := defaults.Normalize(); clamped || defaults.Timeouts != DefaultTimeouts() {
		t.Fatal("filling defaults is not a clamp")
	}

	a := sample[Assist]()
	a.Role, a.From, a.Kind, a.Source = "", RoleServer, AssistPeerTargets, TargetsInject
	a.Targets = repeat(ap("192.0.2.1:9"), 20)
	a.Window = &PortWindow{IP: ip("192.0.2.1"), Lo: 100, Hi: 1000}
	a.Meta = map[string]string{}
	for i := 0; i < 10; i++ {
		a.Meta[fmt.Sprintf("k%02d", i)] = "v"
	}
	n, clamped := a.Normalize()
	if !clamped || len(n.Targets) != 16 || n.Window.Hi != 163 || len(n.Meta) != 8 || n.Meta["k07"] != "v" || n.Meta["k08"] != "" {
		t.Fatalf("Assist after Normalize: %d targets, window %+v, meta %v", len(n.Targets), n.Window, n.Meta)
	}
	if len(a.Targets) != 20 || a.Window.Hi != 1000 || len(a.Meta) != 10 {
		t.Fatal("Normalize wrote the assist's targets, window or meta")
	}
	pr := sample[PunchResult]()
	pr.Stats.Drops = map[string]uint32{}
	for i := 0; i < 20; i++ {
		pr.Stats.Drops[fmt.Sprintf("d%02d", i)] = 1
	}
	if n, clamped := pr.Normalize(); !clamped || len(n.Stats.Drops) != 16 || len(pr.Stats.Drops) != 20 {
		t.Fatalf("drops after Normalize: %d (input %d)", len(n.Stats.Drops), len(pr.Stats.Drops))
	}
	sum := sample[ProbeSummary]()
	sum.Plan.Round1 = sampleRoundPlan(1)
	sum.Plan.RoundsMax = 9
	if n, clamped := sum.Normalize(); !clamped || n.Plan.RoundsMax != 6 {
		t.Fatalf("summary after Normalize: rounds_max %d", n.Plan.RoundsMax)
	}
	rp := sampleRoundPlan(1)
	if c, clamped := rp.ClampTo(Budget{MaxSockets: 1, MaxPPS: 50}); !clamped || c.Sides[0].Sockets != 1 || c.Sides[0].MaxPPS != 50 || c.Sides[0].MaxPackets != 200 {
		t.Fatalf("ClampTo: %+v", c.Sides[0])
	}
	if rp.Sides[0].Sockets == 1 {
		t.Fatal("ClampTo wrote its receiver's sides")
	}
	// Fresh sockets come on top of the side's own in every socket limit:
	// they give way first, and the side's own make room for one at least.
	rp = sampleRoundPlan(1)
	rp.Sides[0].Stages[3] = freshStage(ap("192.0.2.55:61003"))
	rp.Sides[0].Stages[3].Count = 30
	rp, clamped = rp.ClampTo(Budget{MaxSockets: 10})
	if !clamped || rp.Sides[0].Sockets != 2 || rp.Sides[0].FreshSockets() != 8 {
		t.Fatalf("ClampTo with fresh sockets: %d + %d", rp.Sides[0].Sockets, rp.Sides[0].FreshSockets())
	}
	rp, clamped = rp.ClampTo(Budget{MaxSockets: 2})
	if !clamped || rp.Sides[0].Sockets != 1 || rp.Sides[0].FreshSockets() != 1 {
		t.Fatalf("ClampTo with no room: %d + %d", rp.Sides[0].Sockets, rp.Sides[0].FreshSockets())
	}
	rp = sampleRoundPlan(1) // balanced: 8 sockets a side
	rp.Sides[0].Stages[3] = freshStage(ap("192.0.2.55:61003"))
	rp.Sides[0].Stages[3].Count = 30
	balanced, clamped := rp.Normalize()
	if !clamped || balanced.Sides[0].Sockets+uint16(balanced.Sides[0].FreshSockets()) != 8 {
		t.Fatalf("Normalize with fresh sockets: %d + %d", balanced.Sides[0].Sockets, balanced.Sides[0].FreshSockets())
	}
	if rp.Sides[0].Stages[3].Count != 30 {
		t.Fatal("Normalize wrote its receiver's stages")
	}
}

// freshStage is a fresh stage of four sockets aiming at target.
func freshStage(target netip.AddrPort) Stage {
	return Stage{Kind: StageFresh, Count: 4, Repeats: 3, Targets: []netip.AddrPort{target}}
}

func TestTimeoutsAndWire(t *testing.T) {
	if got := (Timeouts{}).Normalize(); got != DefaultTimeouts() {
		t.Fatalf("zero → %+v", got)
	}
	lo := Timeouts{ProbeTimeoutMs: 1, SummaryWaitMs: 1, GoWaitMs: 1, HandshakeTimeoutMs: 1, HandoverTimeoutMs: 1, TransportTimeoutMs: 1, MaxRounds: 0}.Normalize()
	if lo != (Timeouts{500, 1000, 500, 2000, 500, 1000, 5}) {
		t.Fatalf("low clamps %+v", lo)
	}
	hi := Timeouts{1 << 30, 1 << 30, 1 << 30, 1 << 30, 1 << 30, 1 << 30, 200}.Normalize()
	if hi != (Timeouts{10000, 60000, 15000, 60000, 10000, 60000, 6}) {
		t.Fatalf("high clamps %+v", hi)
	}
	in := Timeouts{GoWaitMs: 9000, MaxRounds: 2}.Within(Timeouts{GoWaitMs: 3000, MaxRounds: 6})
	if in.GoWaitMs != 3000 || in.MaxRounds != 2 || in.ProbeTimeoutMs != 2000 {
		t.Fatalf("Within %+v", in)
	}
	for _, tc := range []struct{ in, want WireSpec }{
		{WireSpec{PayloadMin: 0, PayloadMax: 0}, WireSpec{PayloadMin: 48, PayloadMax: 48}},
		{WireSpec{PayloadMin: 93, PayloadMax: 271}, WireSpec{PayloadMin: 93, PayloadMax: 271}},
		{WireSpec{PayloadMin: 300, PayloadMax: 200}, WireSpec{PayloadMin: 300, PayloadMax: 300}},
		{WireSpec{PayloadMin: 2000, PayloadMax: 3000}, WireSpec{PayloadMin: 1024, PayloadMax: 1024}},
	} {
		got, changed := tc.in.Normalize()
		if got != tc.want || changed != (tc.in != tc.want) {
			t.Errorf("%+v.Normalize() = %+v (changed %v), want %+v", tc.in, got, changed, tc.want)
		}
	}
}
