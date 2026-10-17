package protocol

import (
	"testing"
)

// The reason table, written out independently of reason.go:
// reason → class.
var reasonTable = []struct {
	r     Reason
	class ReasonClass
}{
	{"no_common_family", ClassFatal},
	{"no_probe_endpoint", ClassFatal},
	{"probe_timeout", ClassTransient},
	{"udp_blocked", ClassFatal},
	{"local_port_bind_failed", ClassFatal},
	{"control_interrupted", ClassTransient},
	{"control_timeout", ClassTransient},
	{"not_synchronized", ClassTransient},
	{"one_way_udp_only", ClassNATHard},
	{"token_mismatch", ClassFatal},
	{"candidate_timeout", ClassNATHard},
	{"hard_symmetric_random", ClassNATHard},
	{"packet_budget_exceeded", ClassNATHard},
	{"handover_timeout", ClassTransient},
	{"control_version_mismatch", ClassFatal},
	{"protocol_violation", ClassFatal},
	{"invalid_argument", ClassFatal},
	{"peer_offline", ClassTransient},
	{"session_expired", ClassTransient},
	{"server_busy", ClassTransient},
	{"server_shutdown", ClassTransient},
	{"transport_mismatch", ClassFatal},
	{"aborted_by_peer", ClassTransient},
	{"aborted_by_server", ClassTransient},
	{"canceled", ClassCanceled},
	{"internal", ClassFatal},
}

func TestReasonTable(t *testing.T) {
	all := Reasons()
	if len(all) != 26 || len(reasonTable) != 26 {
		t.Fatalf("%d reasons, table %d; want 26", len(all), len(reasonTable))
	}
	seen := map[Reason]bool{}
	for i, row := range reasonTable {
		if all[i] != row.r {
			t.Errorf("Reasons()[%d] = %s, want %s", i, all[i], row.r)
		}
		if seen[row.r] {
			t.Errorf("duplicate %s", row.r)
		}
		seen[row.r] = true
		if row.r.Class() != row.class || !row.r.Known() {
			t.Errorf("%s: class %s; want %s", row.r, row.r.Class(), row.class)
		}
		if !isName(string(row.r), maxName) {
			t.Errorf("%s: not a wire name", row.r)
		}
	}
	if Reason("nope").Known() || Reason("nope").Class() != ClassNone {
		t.Error("unknown reason")
	}
}

// TestOnlyCanonicalReasons: the wire carries only the 26 names. Near misses,
// misspellings and detail-shaped strings are unknown reasons: Known is false,
// the class is none, and a punch_abort carrying one maps to aborted_by_<by>.
func TestOnlyCanonicalReasons(t *testing.T) {
	for _, s := range []string{
		"internal_error", "handover_failed", "server_unavailable", "peer_disconnected", "session_timeout",
		"protocol_error", "version_mismatch", "version_incompatible", "insecure_control", "aborted_by_caller",
		"udp_filtered", "probe_send_failed", "peer_stalled", "control_flood", "panic:udp-read[3]",
		"PROTOCOL_VIOLATION", "aborted", "ErrServerBusy", "",
	} {
		r := Reason(s)
		if r.Known() || r.Class() != ClassNone {
			t.Errorf("%q is known (class %s)", s, r.Class())
		}
	}
}
