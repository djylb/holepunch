package nat

import (
	"testing"

	"github.com/djylb/holepunch/protocol"
)

// DisplayName over the basic combinations.
func TestDisplayNameTable(t *testing.T) {
	h, m := protocol.ConfHigh, protocol.ConfMedium
	base := protocol.Traits{Family: protocol.FamilyUDP4, Samples: 3}
	with := func(f func(*protocol.Traits)) protocol.Traits { t := base; f(&t); return t }
	cases := []struct {
		tr   protocol.Traits
		want string
	}{
		{protocol.Traits{Family: protocol.FamilyUDP4}, "Unknown(no-probe)"},
		{with(func(t *protocol.Traits) { t.NoNAT, t.Filtering = protocol.TriTrue, protocol.FiltEIF }), "Public"},
		{with(func(t *protocol.Traits) { t.NoNAT, t.Filtering = protocol.TriTrue, protocol.FiltPDF }), "Public+Firewall"},
		{with(func(t *protocol.Traits) { t.MultiExit, t.MappingConf = true, protocol.ConfLow }), "MultiExit?"},
		{with(func(t *protocol.Traits) {
			t.Mapping, t.MappingConf, t.PortAlloc, t.PortStep = protocol.MapAPDM, h, protocol.AllocSequential, -2
		}), "Symmetric(step -2)"},
		{with(func(t *protocol.Traits) {
			t.Mapping, t.MappingConf, t.PortAlloc, t.PortStep = protocol.MapAPDM, m, protocol.AllocSequential, 1
		}), "Symmetric(step +1)?"},
		{with(func(t *protocol.Traits) {
			t.Mapping, t.MappingConf, t.PortAlloc, t.PortRangeLo, t.PortRangeHi = protocol.MapAPDM, h, protocol.AllocPool, 31744, 32767
		}), "Symmetric(pool 1024)"},
		{with(func(t *protocol.Traits) {
			t.Mapping, t.MappingConf, t.PortAlloc = protocol.MapAPDM, h, protocol.AllocRandom
		}), "Symmetric(random)"},
		{with(func(t *protocol.Traits) {
			t.Mapping, t.MappingConf, t.PortAlloc = protocol.MapAPDM, m, protocol.AllocPreserveFresh
		}), "Symmetric(fresh-preserving)?"},
		{with(func(t *protocol.Traits) { t.Mapping, t.MappingConf = protocol.MapADM, h }), "AddressDependent"},
		{with(func(t *protocol.Traits) { t.Mapping, t.MappingConf, t.Filtering = protocol.MapEIM, h, protocol.FiltEIF }), "FullCone"},
		{with(func(t *protocol.Traits) { t.Mapping, t.MappingConf, t.Filtering = protocol.MapEIM, m, protocol.FiltADF }), "RestrictedCone?"},
		{with(func(t *protocol.Traits) { t.Mapping, t.MappingConf, t.Filtering = protocol.MapEIM, m, protocol.FiltPDF }), "PortRestrictedCone?"},
		{with(func(t *protocol.Traits) {
			t.Mapping, t.MappingConf, t.Filtering = protocol.MapEIM, m, protocol.FiltNotPDF
		}), "Cone(EIF/ADF)?"},
		{with(func(t *protocol.Traits) { t.Mapping, t.MappingConf = protocol.MapEIM, m }), "Cone(filter-untested)?"},
		{with(func(t *protocol.Traits) { t.MappingConf = protocol.ConfLow }), "Unknown(3 samples)"},
		{with(func(t *protocol.Traits) {
			t.Family, t.Mapping, t.MappingConf, t.Filtering = protocol.FamilyUDP6, protocol.MapEIM, h, protocol.FiltPDF
			t.PortAlloc, t.CGNAT, t.Hairpin = protocol.AllocPreserving, protocol.TriTrue, protocol.TriFalse
		}), "v6:PortRestrictedCone+CGNAT-hairpin+pres"},
		{with(func(t *protocol.Traits) { t.Hairpin, t.MappingConf = protocol.TriTrue, protocol.ConfLow }), "Unknown(3 samples)+hairpin"},
	}
	for _, c := range cases {
		if got := DisplayName(c.tr); got != c.want {
			t.Errorf("DisplayName(%+v) = %q, want %q", c.tr, got, c.want)
		}
	}
}

func TestFingerprintExamples(t *testing.T) {
	v4 := protocol.FamilyUDP4
	cases := []struct {
		tr   protocol.Traits
		want string
	}{
		{protocol.Traits{Family: v4, Mapping: protocol.MapEIM, Filtering: protocol.FiltPDF, PortAlloc: protocol.AllocPreserving}, "v4|EIM|PDF|PRES"},
		{protocol.Traits{Family: v4, Mapping: protocol.MapAPDM, Filtering: protocol.FiltPDF, PortAlloc: protocol.AllocSequential, PortStep: 1}, "v4|APDM|PDF|SEQ+1"},
		{protocol.Traits{Family: v4, Mapping: protocol.MapAPDM, Filtering: protocol.FiltPDF, PortAlloc: protocol.AllocSequential, PortStep: -300}, "v4|APDM|PDF|SEQ-64"},
		{protocol.Traits{Family: v4, Mapping: protocol.MapAPDM, Filtering: protocol.FiltPDF, PortAlloc: protocol.AllocPool, PortRangeLo: 31744, PortRangeHi: 32767}, "v4|APDM|PDF|POOL1024"},
		{protocol.Traits{Family: v4, Mapping: protocol.MapAPDM, Filtering: protocol.FiltADF, PortAlloc: protocol.AllocRandom}, "v4|APDM|ADF|RAND"},
		{protocol.Traits{Family: v4, Mapping: protocol.MapAPDM, Filtering: protocol.FiltPDF, PortAlloc: protocol.AllocPreserveFresh}, "v4|APDM|PDF|FRESH"},
		// A stateful firewall without NAT is written with the
		// PDF token of the Traits enum, not as "FW".
		{protocol.Traits{Family: protocol.FamilyUDP6, NoNAT: protocol.TriTrue, Mapping: protocol.MapEIM, Filtering: protocol.FiltPDF, PortAlloc: protocol.AllocPreserving, Samples: 3}, "v6|NONAT|PDF"},
		{protocol.Traits{Family: v4, MultiExit: true, Filtering: protocol.FiltNotPDF}, "v4|MULTIEXIT|NOTPDF|UNK"},
		{protocol.Traits{}, "v?|UNK|UNK|UNK"},
		{protocol.Traits{Family: v4, Mapping: protocol.Mapping(77), Filtering: protocol.Filtering(9), PortAlloc: protocol.PortAlloc(42)}, "v4|UNK|UNK|UNK"},
	}
	for _, c := range cases {
		if got := Fingerprint(c.tr); got != c.want {
			t.Errorf("Fingerprint = %q, want %q", got, c.want)
		}
	}
}

// ClassBits and Fingerprint correspond one to one.
func TestClassBitsBijection(t *testing.T) {
	byBits := map[uint32]string{}
	byFP := map[string]uint32{}
	check := func(tr protocol.Traits) {
		fp, b := Fingerprint(tr), ClassBits(tr)
		if old, ok := byBits[b]; ok && old != fp {
			t.Fatalf("bits %#x for %q and %q", b, old, fp)
		}
		if old, ok := byFP[fp]; ok && old != b {
			t.Fatalf("fingerprint %q has bits %#x and %#x", fp, old, b)
		}
		byBits[b], byFP[fp] = fp, b
	}
	for _, fam := range []protocol.Family{"", protocol.FamilyUDP4, protocol.FamilyUDP6, "udp9"} {
		for _, nonat := range []protocol.Tri{protocol.TriUnknown, protocol.TriFalse, protocol.TriTrue} {
			for _, mx := range []bool{false, true} {
				for mp := range protocol.Mapping(5) {
					for fl := range protocol.Filtering(6) {
						for al := range protocol.PortAlloc(6) {
							tr := protocol.Traits{Family: fam, NoNAT: nonat, MultiExit: mx, Mapping: mp, Filtering: fl, PortAlloc: al}
							switch al {
							case protocol.AllocSequential:
								for step := -70; step <= 70; step++ {
									tr.PortStep = int16(step)
									check(tr)
								}
							case protocol.AllocPool:
								for _, r := range [][2]uint16{{0, 0}, {5, 4}, {100, 101}, {31744, 32767}, {0, 65535}, {64512, 65535}, {1000, 3000}} {
									tr.PortRangeLo, tr.PortRangeHi = r[0], r[1]
									check(tr)
								}
							default:
								check(tr)
							}
						}
					}
				}
			}
		}
	}
	if len(byBits) != len(byFP) || len(byBits) < 1000 {
		t.Fatalf("%d bit patterns, %d fingerprints", len(byBits), len(byFP))
	}
	for b := range byBits {
		if b>>19 != 0 {
			t.Fatalf("bits %#x use the reserved range", b)
		}
	}
}

func TestCorrection(t *testing.T) {
	prev := protocol.Traits{Family: protocol.FamilyUDP4, Mapping: protocol.MapEIM, MappingConf: protocol.ConfMedium,
		Filtering: protocol.FiltPDF, FilteringConf: protocol.ConfHigh}
	if _, ok := Correction(prev, prev, protocol.TraitsSourcePeer); ok {
		t.Fatal("no change reported as a correction")
	}
	cur := prev
	cur.Mapping, cur.MappingConf, cur.Hairpin = protocol.MapADM, protocol.ConfHigh, protocol.TriTrue
	u, ok := Correction(prev, cur, protocol.TraitsSourcePeer)
	if !ok || *u.Mapping != protocol.MapADM || *u.MappingConf != protocol.ConfHigh || *u.Hairpin != protocol.TriTrue ||
		u.Filtering != nil || u.FilteringConf != nil || u.PortStep != nil || u.PortVelocity != nil ||
		u.Source != protocol.TraitsSourcePeer || u.Family != protocol.FamilyUDP4 {
		t.Fatalf("update %+v", u)
	}
	cur = prev
	cur.Filtering, cur.FilteringConf, cur.PortStep, cur.PortVelocity = protocol.FiltEIF, protocol.ConfMedium, 2, 30
	u, ok = Correction(prev, cur, protocol.TraitsSourceAlt)
	if !ok || *u.Filtering != protocol.FiltEIF || *u.FilteringConf != protocol.ConfMedium || *u.PortStep != 2 || *u.PortVelocity != 30 || u.Mapping != nil {
		t.Fatalf("update %+v", u)
	}
	res := protocol.PunchResult{SessionID: "s1", Role: protocol.RoleInitiator, Code: protocol.ReasonCandidateTimeout,
		Phase: protocol.PhaseFailed, Traits: []protocol.TraitsUpdate{u}}
	if err := res.Validate(); err != nil {
		t.Fatalf("punch_result with the update: %v", err)
	}
}
