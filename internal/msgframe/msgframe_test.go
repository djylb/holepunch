package msgframe

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"testing"

	"github.com/djylb/holepunch/internal/controlwire"
	"github.com/djylb/holepunch/protocol"
)

func TestAbortReason(t *testing.T) {
	for _, tc := range []struct {
		by   protocol.Role
		code protocol.Reason
		want protocol.Reason
	}{
		{protocol.RoleServer, protocol.ReasonServerBusy, protocol.ReasonServerBusy},
		{protocol.RoleResponder, protocol.ReasonNoCommonFamily, protocol.ReasonNoCommonFamily},
		{protocol.RoleServer, "", protocol.ReasonAbortedByServer},
		{protocol.RoleServer, "future_code", protocol.ReasonAbortedByServer},
		{protocol.RoleInitiator, "", protocol.ReasonAbortedByPeer},
		{protocol.RoleResponder, "future_code", protocol.ReasonAbortedByPeer},
	} {
		if got := AbortReason(tc.by, tc.code); got != tc.want {
			t.Errorf("AbortReason(%s, %q) = %s, want %s", tc.by, tc.code, got, tc.want)
		}
	}
}

func TestReason(t *testing.T) {
	for _, tc := range []struct {
		err    error
		reason protocol.Reason
		detail string
		ok     bool
	}{
		{nil, "", "", false},
		{fmt.Errorf("x: %w", controlwire.ErrVersion), protocol.ReasonControlVersionMismatch, "frame_version", true},
		{controlwire.ErrBadMagic, protocol.ReasonProtocolViolation, "bad_magic", true},
		{controlwire.ErrZeroType, protocol.ReasonProtocolViolation, "zero_type", true},
		{controlwire.ErrFrameTooLarge, protocol.ReasonProtocolViolation, "frame_too_large", true},
		{controlwire.ErrTooManyUnknown, protocol.ReasonProtocolViolation, "unknown_frames", true},
		{controlwire.ErrFlood, protocol.ReasonProtocolViolation, "control_flood", true},
		{controlwire.ErrDeadlineUnsupported, protocol.ReasonInvalidArgument, "deadline_unsupported", true},
		{controlwire.ErrNilConn, protocol.ReasonInvalidArgument, "nil_control", true},
		{fmt.Errorf("%w: x", protocol.ErrUnexpectedMessage), protocol.ReasonProtocolViolation, "unexpected_message", true},
		{protocol.Ping{}.Validate(), protocol.ReasonProtocolViolation, "seq", true},
		// Everything else is the caller's to classify.
		{controlwire.ErrReleased, "", "", false},
		{net.ErrClosed, "", "", false},
		{context.Canceled, "", "", false},
		{io.EOF, "", "", false},
		{&net.OpError{Op: "write", Err: os.ErrDeadlineExceeded}, "", "", false},
	} {
		r, d, ok := Reason(tc.err)
		if r != tc.reason || d != tc.detail || ok != tc.ok {
			t.Errorf("Reason(%v) = %s %q %v, want %s %q %v", tc.err, r, d, ok, tc.reason, tc.detail, tc.ok)
		}
	}
}
