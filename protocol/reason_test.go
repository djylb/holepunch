package protocol

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"testing"

	"github.com/djylb/holepunch/controlwire"
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

func TestAbortReason(t *testing.T) {
	for _, tc := range []struct {
		by   Role
		code Reason
		want Reason
	}{
		{RoleServer, ReasonServerBusy, ReasonServerBusy},
		{RoleResponder, ReasonNoCommonFamily, ReasonNoCommonFamily},
		{RoleServer, "", ReasonAbortedByServer},
		{RoleServer, "future_code", ReasonAbortedByServer},
		{RoleInitiator, "", ReasonAbortedByPeer},
		{RoleResponder, "future_code", ReasonAbortedByPeer},
	} {
		if got := AbortReason(tc.by, tc.code); got != tc.want {
			t.Errorf("AbortReason(%s, %q) = %s, want %s", tc.by, tc.code, got, tc.want)
		}
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
		if AbortReason(RoleServer, r) != ReasonAbortedByServer || AbortReason(RoleInitiator, r) != ReasonAbortedByPeer {
			t.Errorf("AbortReason(%q) does not map to aborted_by_<by>", s)
		}
	}
}

func TestWireReason(t *testing.T) {
	for _, tc := range []struct {
		err    error
		reason Reason
		detail string
		ok     bool
	}{
		{nil, "", "", false},
		{fmt.Errorf("x: %w", controlwire.ErrVersion), ReasonControlVersionMismatch, "frame_version", true},
		{controlwire.ErrBadMagic, ReasonProtocolViolation, "bad_magic", true},
		{controlwire.ErrZeroType, ReasonProtocolViolation, "zero_type", true},
		{controlwire.ErrFrameTooLarge, ReasonProtocolViolation, "frame_too_large", true},
		{controlwire.ErrTooManyUnknown, ReasonProtocolViolation, "unknown_frames", true},
		{controlwire.ErrFlood, ReasonProtocolViolation, "control_flood", true},
		{controlwire.ErrDeadlineUnsupported, ReasonInvalidArgument, "deadline_unsupported", true},
		{controlwire.ErrNilConn, ReasonInvalidArgument, "nil_control", true},
		{fmt.Errorf("%w: x", ErrUnexpectedMessage), ReasonProtocolViolation, "unexpected_message", true},
		{Ping{}.Validate(), ReasonProtocolViolation, "seq", true},
		{ProbeSpec{V: 2}.validate("probe"), ReasonControlVersionMismatch, "probe_v", true},
		// Everything else is the caller's to classify.
		{controlwire.ErrReleased, "", "", false},
		{net.ErrClosed, "", "", false},
		{context.Canceled, "", "", false},
		{io.EOF, "", "", false},
		{&net.OpError{Op: "write", Err: os.ErrDeadlineExceeded}, "", "", false},
	} {
		r, d, ok := WireReason(tc.err)
		if r != tc.reason || d != tc.detail || ok != tc.ok {
			t.Errorf("WireReason(%v) = %s %q %v, want %s %q %v", tc.err, r, d, ok, tc.reason, tc.detail, tc.ok)
		}
	}
}
