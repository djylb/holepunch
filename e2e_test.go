package holepunch

import (
	"testing"

	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

func natCfg(c nattest.NATConfig) *nattest.NATConfig { return &c }

func TestPairPortRestricted(t *testing.T) {
	w := newWorld(t)
	ps := &pairScript{w: w, timeouts: testTimeouts()}
	pr := runPair(t, w, [2]*nattest.NATConfig{natCfg(nattest.PortRestricted()), natCfg(nattest.PortRestricted())}, ps, nil)
	defer pr.closeAll()
	for i, r := range pr.res {
		if r.err != nil {
			t.Fatalf("client %d: %v (script: %v)", i, r.err, pr.scriptE)
		}
		res := r.sess.Result()
		if res.Path.Family != protocol.FamilyUDP4 || !res.Path.RemoteAddr.IsValid() {
			t.Fatalf("client %d result %+v", i, res)
		}
		t.Logf("client %d: %+v path=%+v", i, res, r.sess.Diagnostics().Path)
	}
}
