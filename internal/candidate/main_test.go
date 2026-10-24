package candidate

import (
	"net/netip"
	"testing"

	"github.com/djylb/holepunch/internal/goroutines"
)

func TestMain(m *testing.M) {
	goroutines.VerifyTestMain(m)
}

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }
