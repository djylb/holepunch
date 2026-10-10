package plan

import (
	"testing"

	"github.com/djylb/holepunch/protocol"
)

func TestCategoryTable(t *testing.T) {
	f := protocol.FamilyUDP4
	cases := []struct {
		name string
		tr   protocol.Traits
		want Category
	}{
		{"nonat_open", protocol.Traits{Family: f, NoNAT: protocol.TriTrue, Filtering: protocol.FiltEIF, Samples: 2}, CatOpen},
		{"eim_high_eif_open", openTraits(f), CatOpen},
		{"eim_high_pdf", pdfTraits(f), CatPDF},
		{"eim_medium_adf_open", protocol.Traits{Family: f, Mapping: protocol.MapEIM, MappingConf: protocol.ConfMedium, Filtering: protocol.FiltADF, Samples: 2}, CatOpen},
		{"eim_low_falls_to_pdf", protocol.Traits{Family: f, Mapping: protocol.MapEIM, MappingConf: protocol.ConfLow, Filtering: protocol.FiltEIF, Samples: 2}, CatPDF},
		{"unknown_mapping_pdf", protocol.Traits{Family: f, Mapping: protocol.MapUnknown, Samples: 1}, CatPDF},
		{"apdm_seq", seqTraits(f), CatSEQ},
		{"adm_predictable_seq", protocol.Traits{Family: f, Mapping: protocol.MapADM, Filtering: protocol.FiltPDF, PortAlloc: protocol.AllocSequential, PortAllocConf: protocol.ConfHigh, PortStep: 1, Samples: 4}, CatSEQ},
		{"adm_pool_medium_seq", protocol.Traits{Family: f, Mapping: protocol.MapADM, Filtering: protocol.FiltPDF, PortAlloc: protocol.AllocPool, PortAllocConf: protocol.ConfMedium, Samples: 4}, CatSEQ},
		{"apdm_rnd", rndTraits(f), CatRND},
		{"apdm_pool_low_rnd", protocol.Traits{Family: f, Mapping: protocol.MapAPDM, Filtering: protocol.FiltPDF, PortAlloc: protocol.AllocPool, PortAllocConf: protocol.ConfLow, Samples: 4}, CatRND},
		{"samples_zero_none", protocol.Traits{Family: f, Mapping: protocol.MapEIM, MappingConf: protocol.ConfHigh, Samples: 0}, CatNone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := CategoryOf(c.tr); got != c.want {
				t.Fatalf("CategoryOf = %v, want %v", got, c.want)
			}
		})
	}
}

func TestPairClassCombinations(t *testing.T) {
	cases := []struct {
		a, b Category
		want string
	}{
		{CatOpen, CatOpen, PairEasy},
		{CatOpen, CatPDF, PairEasy},
		{CatPDF, CatPDF, PairEasy},
		{CatOpen, CatSEQ, PairOpenEDM},
		{CatOpen, CatRND, PairOpenEDM},
		{CatPDF, CatSEQ, PairPDFSeq},
		{CatPDF, CatRND, PairPDFRnd},
		{CatSEQ, CatSEQ, PairSeqSeq},
		{CatSEQ, CatRND, PairSeqRnd},
		{CatRND, CatRND, PairRndRnd},
		{CatNone, CatOpen, PairNoCommon},
	}
	for _, c := range cases {
		if got := PairClass(c.a, c.b); got != c.want {
			t.Errorf("PairClass(%v,%v) = %q, want %q", c.a, c.b, got, c.want)
		}
		if got := PairClass(c.b, c.a); got != c.want { // order-independent
			t.Errorf("PairClass(%v,%v) = %q, want %q (order)", c.b, c.a, got, c.want)
		}
	}
}

func TestOpensBirthday(t *testing.T) {
	f := protocol.FamilyUDP4
	if !opensBirthday(rndTraits(f)) {
		t.Error("RND should open birthday")
	}
	if !opensBirthday(seqTraits(f)) {
		t.Error("SEQ should open birthday")
	}
	unkF := rndTraits(f)
	unkF.Filtering = protocol.FiltUnknown
	if opensBirthday(unkF) {
		t.Error("unknown filtering must not open birthday")
	}
	unkM := rndTraits(f)
	unkM.Mapping = protocol.MapUnknown
	if opensBirthday(unkM) {
		t.Error("unknown mapping must not open birthday")
	}
}
