package candidate

import (
	"net/netip"
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }
