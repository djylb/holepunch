package protocol

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/djylb/holepunch/controlwire"
)

// jsonFields lists the JSON names of t's fields; a name ending in "?" is
// omitempty/omitzero.
func jsonFields(t reflect.Type) []string {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice {
		t = t.Elem()
	}
	var out []string
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		name, opts, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			out = append(out, "!untagged:"+t.Field(i).Name)
			continue
		}
		if strings.Contains(opts, "omitempty") || strings.Contains(opts, "omitzero") {
			name += "?"
		}
		out = append(out, name)
	}
	return out
}

// checkFields compares t's JSON fields with the wire field list, in any
// order: declarations follow memory layout, and a JSON object is unordered.
// A "?" in want (an optional field) must be omitempty in the code; a field
// without "?" may still be omitempty where the protocol defines it so.
func checkFields(t *testing.T, what string, typ reflect.Type, want ...string) {
	t.Helper()
	got := jsonFields(typ)
	optional := make(map[string]bool, len(got))
	for _, g := range got {
		name, opt := strings.CutSuffix(g, "?")
		optional[name] = opt
	}
	if len(optional) != len(got) || len(got) != len(want) {
		t.Errorf("%s: fields %v, want %v", what, got, want)
		return
	}
	for _, w := range want {
		name, opt := strings.CutSuffix(w, "?")
		gotOpt, ok := optional[name]
		switch {
		case !ok:
			t.Errorf("%s: no field %q (all: %v)", what, name, got)
		case opt && !gotOpt:
			t.Errorf("%s: field %q is not omitempty (all: %v)", what, name, got)
		}
	}
}

func typeOf[T any]() reflect.Type { return reflect.TypeFor[T]() }

// allMessageTypes lists the twelve message types in type-number order.
func allMessageTypes() []MessageType {
	return []MessageType{MsgPunchStart, MsgProbeReport, MsgProbeSummary, MsgPunchReady, MsgPunchGo, MsgProgress,
		MsgAssist, MsgAbort, MsgPing, MsgPong, MsgRoundResult, MsgPunchResult}
}

// messageTypeNamed returns the message type whose wire name is name.
func messageTypeNamed(t testing.TB, name string) MessageType {
	t.Helper()
	for _, typ := range allMessageTypes() {
		if typ.String() == name {
			return typ
		}
	}
	t.Fatalf("no message type named %q", name)
	return 0
}

// TestProtocolTable pins the twelve message types — numbered contiguously
// from 1 in table order, every higher number reserved — and every field
// name of the wire format.
func TestProtocolTable(t *testing.T) {
	type row struct {
		typ    MessageType
		name   string
		from   string // "server", "client", "both"
		cap    int
		goType reflect.Type
		fields []string
	}
	rows := []row{
		{MsgPunchStart, "punch_start", "server", 16 << 10, typeOf[PunchStart](),
			[]string{"session_id", "role", "token", "wire", "control", "probe", "timeouts", "policy?", "mode?"}},
		{MsgProbeReport, "probe_report", "client", 32 << 10, typeOf[ProbeReport](),
			[]string{"session_id", "role", "control", "caps", "elapsed_ms", "families", "clock", "transport", "mode?"}},
		{MsgProbeSummary, "probe_summary", "server", 48 << 10, typeOf[ProbeSummary](),
			[]string{"session_id", "self", "peer", "pair", "transport", "timeouts", "plan"}},
		{MsgPunchReady, "punch_ready", "client", 1 << 10, typeOf[PunchReady](),
			[]string{"session_id", "role", "elapsed_ms", "families"}},
		{MsgPunchGo, "punch_go", "server", 8 << 10, typeOf[PunchGo](),
			[]string{"session_id", "round", "delay_ms", "window_ms", "final?", "rtt_ms?", "plan?"}},
		{MsgProgress, "punch_progress", "client", 2 << 10, typeOf[Progress](),
			[]string{"session_id", "role", "seq", "stage", "status", "round?", "at_ms", "detail?", "counters?", "meta?"}},
		{MsgAssist, "punch_assist", "both", 1 << 10, typeOf[Assist](),
			[]string{"session_id", "role", "from", "kind", "round", "family", "remote", "local", "sock", "cand", "type", "first?",
				"targets", "window", "source", "meta?"}},
		{MsgAbort, "punch_abort", "server", 1 << 10, typeOf[Abort](),
			[]string{"session_id", "by", "code", "detail?", "retry_after_ms?"}},
		{MsgPing, "ping", "server", 256, typeOf[Ping](), []string{"seq"}},
		{MsgPong, "pong", "client", 256, typeOf[Pong](), []string{"seq", "hold_us", "client_unix_ms"}},
		{MsgRoundResult, "round_result", "client", 4 << 10, typeOf[RoundResult](),
			[]string{"session_id", "role", "round", "elapsed_ms", "fire_skew_ms", "status", "code?", "families", "path?"}},
		{MsgPunchResult, "punch_result", "client", 8 << 10, typeOf[PunchResult](),
			[]string{"session_id", "role", "ok", "code?", "phase", "detail?", "path?", "extra_paths?", "stats", "timing", "traits", "warn"}},
	}
	if all := allMessageTypes(); len(all) != len(rows) {
		t.Fatalf("allMessageTypes has %d types, the table %d", len(all), len(rows))
	}
	for i, r := range rows {
		b := uint8(r.typ)
		if int(r.typ) != i+1 || allMessageTypes()[i] != r.typ {
			t.Errorf("%s is type %d at table position %d: types are numbered contiguously from 1", r.name, b, i+1)
		}
		if r.typ.String() != r.name || r.typ.MaxPayload() != r.cap {
			t.Errorf("type %d: name %q cap %d; want %q %d", b, r.typ, r.typ.MaxPayload(), r.name, r.cap)
		}
		ct := controlwire.Type(r.typ)
		clientSends, serverSends := controlwire.SideClient.Sends(ct), controlwire.SideServer.Sends(ct)
		wantClient, wantServer := r.from == "client" || r.from == "both", r.from == "server" || r.from == "both"
		if clientSends != wantClient || serverSends != wantServer {
			t.Errorf("type %d: client sends %v, server sends %v; want %s", b, clientSends, serverSends, r.from)
		}
		// A side accepts exactly what the other side sends.
		if controlwire.SideServer.Receives(ct) != wantClient || controlwire.SideClient.Receives(ct) != wantServer {
			t.Errorf("type %d: accepted on the wrong side", b)
		}
		if !r.typ.Known() {
			t.Errorf("type %d not known", b)
		}
		m := reflect.Zero(r.goType).Interface().(Message)
		if m.MessageType() != r.typ {
			t.Errorf("%s: MessageType() = %d", r.name, m.MessageType())
		}
		checkFields(t, r.name, r.goType, r.fields...)
	}
	for b := int(MsgPunchResult) + 1; b <= math.MaxUint8; b++ {
		typ := MessageType(b)
		if typ.Known() || typ.MaxPayload() != controlwire.DiscardCap || typ.String() != fmt.Sprintf("type(%d)", b) {
			t.Errorf("type %d: known %v, cap %d, name %q; want a reserved type", b, typ.Known(), typ.MaxPayload(), typ)
		}
		if _, err := Decode(controlwire.Frame{Type: controlwire.Type(b), Payload: []byte("{}")}); !errors.Is(err, ErrUnexpectedMessage) {
			t.Errorf("Decode of reserved type %d = %v", b, err)
		}
	}

	// Shared sub-structures.
	checkFields(t, "wire", typeOf[WireSpec](), "route_id", "payload_min", "payload_max")
	checkFields(t, "control", typeOf[ControlSpec](), "version", "features?")
	checkFields(t, "policy", typeOf[Policy](), "budget", "port_mapping", "low_ttl?", "low_ttl_hops?")
	checkFields(t, "budget", typeOf[Budget](), "max_packets", "max_pps", "max_distinct_targets", "max_sockets", "max_new_per_sec", "birthday")
	checkFields(t, "port_mapping", typeOf[PortMappingPolicy](), "upnp", "pcp", "natpmp", "lease_seconds")
	checkFields(t, "timeouts", typeOf[Timeouts](), "probe_timeout_ms", "summary_wait_ms", "go_wait_ms", "handshake_timeout_ms",
		"handover_timeout_ms", "transport_timeout_ms", "max_rounds")
	checkFields(t, "caps", typeOf[ClientCaps](), "impl", "families", "max_sockets", "port_map")
	checkFields(t, "caps.families", typeOf[FamilyCaps](), "family", "low_ttl", "recv_err?")
	checkFields(t, "clock", typeOf[ClockSample](), "rtt_ms", "offset_ms")
	checkFields(t, "transport", typeOf[Transport](), "mode", "data")
	checkFields(t, "summary.transport", typeOf[TransportPick](), "mode", "peer_data")
	checkFields(t, "pair", typeOf[PairFacts](), "shared_families", "same_public_ip", "same_lan", "shared_overlay?", "probe_rtt_ms", "clock_offset_ms", "unverified?")
	checkFields(t, "ready.families", typeOf[FamilyReady](), "family", "sockets", "clamped?", "rejected?", "port_map?")
	checkFields(t, "assist.window", typeOf[PortWindow](), "ip", "lo", "hi")
	checkFields(t, "round_result.families", typeOf[FamilyOutcome](), "family", "hit", "seen_from", "peer_seen_us", "sent", "recv",
		"distinct_ports", "icmp_unreach?", "bind_failed?", "budget_hit?", "drift?", "rejected?", "remap?", "halted?")
	checkFields(t, "round_result.families.remap", typeOf[Remap](), "o", "a", "c")
	checkFields(t, "stats", typeOf[Stats](), "sent", "recv", "replies", "rounds", "hits", "drops", "budget_hit?")
	checkFields(t, "timing", typeOf[Timing](), "probe_ms", "summary_wait_ms", "go_wait_ms", "punch_ms", "handover_ms")
	checkFields(t, "ProbeSpec", typeOf[ProbeSpec](), "v", "observers", "extra", "second_socket", "siblings", "stun?", "rtt_hint_ms?")
	checkFields(t, "ProbeSpec.observers", typeOf[ObserverSpec](), "id", "addr", "group", "alt?")
	checkFields(t, "FamilyReport", typeOf[FamilyReport](), "family", "failure?", "sockets", "filters", "stun?", "port_map?", "local_addrs", "overlay?", "traits")
	checkFields(t, "punch_assist (peer_targets window)", typeOf[PortWindow](), "ip", "lo", "hi")
	checkFields(t, "FamilyReport.sockets", typeOf[SocketReport](), "id", "kind", "local", "rows")
	checkFields(t, "FamilyReport.rows", typeOf[RowReport](), "o", "a?", "tx", "s", "rtt?", "c")
	checkFields(t, "FamilyReport.filters", typeOf[FilterReport](), "socket", "observer", "extra_seen", "alt_seen")
	checkFields(t, "port_map", typeOf[PortMapReport](), "method", "external", "internal", "lease_seconds")
	checkFields(t, "PeerView", typeOf[PeerView](), "families")
	checkFields(t, "FamilyView", typeOf[FamilyView](), "family", "traits", "endpoints")
	checkFields(t, "Endpoint", typeOf[Endpoint](), "addr", "src", "sock", "v")
	checkFields(t, "Traits", typeOf[Traits](), "family", "no_nat", "mapping", "mapping_conf", "filtering", "filtering_conf", "port_alloc",
		"port_alloc_conf", "port_step", "port_velocity", "port_noisy", "port_anchor", "port_anchor_ms", "port_lo", "port_hi", "first_preserved",
		"multi_exit", "multi_homed", "drifted", "hairpin", "cgnat", "cross_ip", "path_dependent?", "public_ip", "observed", "samples", "provisional")
	checkFields(t, "TraitsUpdate", typeOf[TraitsUpdate](), "family", "mapping?", "mapping_conf?", "filtering?", "filtering_conf?",
		"port_step?", "port_velocity?", "hairpin?", "source")
	checkFields(t, "PlanSpec", typeOf[PlanSpec](), "id", "pair_class", "rounds_max", "ladder?", "budget", "round1", "mode?", "advice?", "background_only?")
	checkFields(t, "RoundPlan", typeOf[RoundPlan](), "round", "variant", "budget", "window_ms", "final?", "rescue?", "seed", "sides")
	checkFields(t, "FamilySide", typeOf[FamilySide](), "family", "role", "send_delay_ms", "sockets", "max_packets", "max_pps",
		"max_new_per_sec", "max_distinct_ports", "open_per_sec?", "sandwich?", "stages")
	checkFields(t, "Stage", typeOf[Stage](), "kind", "at_ms", "targets", "ip", "anchor", "steps", "span", "count", "lo?", "hi?", "repeats", "ttl", "pair?")
	checkFields(t, "PathInfo", typeOf[PathInfo](), "family", "local", "remote", "round", "epoch", "sock", "cand", "cand_kind", "kind", "rtt_ms", "confirmed_by?")
}

// TestEnumValues pins the wire text of every enumeration and the text round
// trip of the uint8-kind ones.
func TestEnumValues(t *testing.T) {
	texts := func(n int, f func(i int) ([]byte, error)) []string {
		var out []string
		for i := 0; i < n; i++ {
			b, err := f(i)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, string(b))
		}
		return out
	}
	for name, tc := range map[string]struct {
		got  []string
		want string
	}{
		"mapping":   {texts(4, func(i int) ([]byte, error) { return Mapping(i).MarshalText() }), "unknown eim adm apdm"},
		"filtering": {texts(5, func(i int) ([]byte, error) { return Filtering(i).MarshalText() }), "unknown eif adf pdf not_pdf"},
		"portalloc": {texts(6, func(i int) ([]byte, error) { return PortAlloc(i).MarshalText() }), "unknown preserving sequential pool random preserve_fresh"},
		"conf":      {texts(4, func(i int) ([]byte, error) { return Conf(i).MarshalText() }), "none low medium high"},
		"tri":       {texts(3, func(i int) ([]byte, error) { return Tri(i).MarshalText() }), "unknown false true"},
		"security":  {texts(3, func(i int) ([]byte, error) { return ControlSecurity(i).MarshalText() }), "unknown declared insecure_for_testing"},
		"class":     {texts(5, func(i int) ([]byte, error) { return ReasonClass(i).MarshalText() }), "none fatal transient nat_hard canceled"},
	} {
		if strings.Join(tc.got, " ") != tc.want {
			t.Errorf("%s: %v, want %s", name, tc.got, tc.want)
		}
	}
	for i := 0; i < 5; i++ {
		var f Filtering
		b, _ := Filtering(i).MarshalText()
		if err := f.UnmarshalText(b); err != nil || f != Filtering(i) {
			t.Errorf("filtering %d round trip: %v %v", i, f, err)
		}
	}
	m := MapEIM
	if err := m.UnmarshalText([]byte("EIM")); err == nil || m.String() != "eim" {
		t.Errorf("UnmarshalText(EIM) = %v, mapping %v: want an error and no change", err, m)
	}
	if _, err := Mapping(9).MarshalText(); err == nil {
		t.Error("MarshalText of an out-of-range mapping succeeded")
	}
	for _, s := range []string{"udp4", "udp6"} {
		if !Family(s).Valid() {
			t.Errorf("family %s invalid", s)
		}
	}
	for _, p := range []Phase{"created", "probing", "reported", "planned", "ready", "punching", "negotiating", "confirmed", "handover", "done", "failed"} {
		if !p.Valid() {
			t.Errorf("phase %s invalid", p)
		}
	}
	if Phase("finished").Valid() || !PhaseDone.Terminal() || PhaseHandover.Terminal() {
		t.Error("phase predicates")
	}
	// The closed string sets of the wire format.
	for name, tc := range map[string]struct {
		got  []string
		want string
	}{
		"stage kind": {strs(StageDirect, StagePredict, StageRandom, StageReplyOnly, StageFresh, StageFreshPeer),
			"direct predict random reply_only fresh fresh_peer"},
		"side role":      {strs(SideSender, SideReceiver, SideBoth, SideReplyOnly), "sender receiver both reply_only"},
		"round status":   {strs(RoundWindowEnd, RoundBudgetExhausted, RoundConfirmed, RoundFatal), "window_end budget_exhausted confirmed fatal"},
		"progress":       {strs(StatusOK, StatusFail, StatusInfo), "ok fail info"},
		"assist kind":    {strs(AssistPeerSeen, AssistPeerTargets, AssistRefresh), "peer_seen peer_targets refresh"},
		"targets source": {strs(TargetsSandwich, TargetsInject, TargetsDrift, TargetsPortmap), "sandwich inject drift portmap"},
		"cand_kind": {strs(CandDirect, CandPredicted, CandRandom, CandBirthday, CandPeerReflexive, CandLAN, CandTargets, CandOverlay),
			"direct predicted random birthday peer_reflexive lan targets overlay"},
		"path kind":     {strs(PathPublic, PathLAN, PathOverlay, PathPortmap), "public lan overlay portmap"},
		"confirmed_by":  {strs(ConfirmedByAck, ConfirmedByUpperLayer, ConfirmedByQuiet, ConfirmedByReady), "ack upper_layer quiet ready"},
		"endpoint src":  {strs(EndpointServer, EndpointSecond, EndpointSibling, EndpointSTUN, EndpointPortmap, EndpointLAN, EndpointOverlay), "server second sibling stun portmap lan overlay"},
		"socket kind":   {strs(SocketPrimary, SocketSecond, SocketSibling), "primary second sibling"},
		"traits source": {strs(TraitsSourcePeer, TraitsSourceAlt, TraitsSourceSTUN, TraitsSourceHairpin), "peer alt stun hairpin"},
		"port_map":      {strs(PortMapUPnP, PortMapPCP, PortMapNATPMP), "upnp pcp natpmp"},
		"budget class":  {strs(BudgetLight, BudgetBalanced, BudgetHeavy, BudgetExtreme, BudgetBackground), "light balanced heavy extreme background"},
		"session mode":  {strs(ModeInteractive, ModeBackground), "interactive background"},
		"advice":        {strs(AdviceBackgroundViable, AdviceRelayOnly), "background_viable relay_only"},
		"birthday tier": {strs(BirthdayOff, BirthdayConservative, BirthdayBalanced, BirthdayAggressive), "off conservative balanced aggressive"},
		"feature":       {strs(SupportedFeatures()...), "sandwich"},
		"warn": {strs(WarnClockSkew, WarnGoroutineJoinTimeout, WarnLowTTLUnsupported, WarnPeerResultMissing, WarnUnverifiedTargets, WarnInsecureControlForTesting, WarnInterfaceListUnavailable),
			"clock_skew goroutine_join_timeout low_ttl_unsupported peer_result_missing unverified_targets insecure_control_for_testing interface_list_unavailable"},
		"drops": {DropKeys(), "short foreign rate auth payload role replay budget target_rejected send_err"},
	} {
		if strings.Join(tc.got, " ") != tc.want {
			t.Errorf("%s: %v, want %s", name, tc.got, tc.want)
		}
	}
	if RoleInitiator.Peer() != RoleResponder || RoleResponder.Peer() != RoleInitiator || RoleServer.Peer() != "" {
		t.Error("Role.Peer")
	}
	if RoleServer.IsPunch() || !RoleServer.Valid() || Role("x").Valid() {
		t.Error("Role predicates")
	}
	if RoleInitiator.Code() != 1 || RoleResponder.Code() != 2 || RoleServer.Code() != 3 || Role("").Code() != 0 {
		t.Error("Role.Code")
	}
}

func strs[T ~string](vs ...T) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = string(v)
	}
	return out
}
