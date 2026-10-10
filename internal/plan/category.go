package plan

import "github.com/djylb/holepunch/protocol"

// Category is one side's NAT-combination class, the only thing ladder
// selection needs from the traits. CategoryOf
// derives it from a side's protocol.Traits; a pair of categories names the
// ladder (PairClass).
type Category uint8

const (
	// CatNone means Samples == 0: no worker is built for this family.
	CatNone Category = iota
	// CatOpen means endpoint-independent mapping and non-port-dependent
	// filtering.
	CatOpen
	// CatPDF means endpoint-independent mapping with port-dependent or
	// unknown filtering, or an unknown mapping with at least one sample.
	CatPDF
	// CatSEQ means address(-and-port)-dependent mapping whose next port is
	// predictable (Predictable: sequential, or a pool at medium confidence).
	CatSEQ
	// CatRND means address(-and-port)-dependent mapping that is not
	// predictable.
	CatRND
)

var categoryNames = [...]string{"none", "open", "pdf", "seq", "rnd"}

// String returns the lowercase category name.
func (c Category) String() string {
	if int(c) < len(categoryNames) {
		return categoryNames[c]
	}
	return "invalid"
}

// rank orders categories from most open to least: open < pdf < seq < rnd.
func (c Category) rank() int {
	switch c {
	case CatOpen:
		return 0
	case CatPDF:
		return 1
	case CatSEQ:
		return 2
	case CatRND:
		return 3
	default: // CatNone or out of range
		return -1
	}
}

// CategoryOf maps a side's traits to its Category. Each rule is a condition
// on a single side's fields, so the mapping is per side; a pair is formed by
// PairClass. OPEN and PDF need an
// endpoint-independent mapping (NoNAT, or EIM at medium confidence or better);
// an address-dependent mapping is SEQ when protocol.Traits.Predictable holds
// (ADM counts) and RND otherwise. An unknown mapping with
// evidence is PDF, the conservative "endpoint-independent but uncertain" class.
func CategoryOf(t protocol.Traits) Category {
	if t.Samples == 0 {
		return CatNone
	}
	if openMapping(t) {
		if t.AcceptsAfterIPContact() {
			return CatOpen
		}
		return CatPDF // PDF or Unknown filtering
	}
	if t.Mapping == protocol.MapUnknown {
		return CatPDF
	}
	if t.EndpointDependent() {
		if t.Predictable() {
			return CatSEQ
		}
		return CatRND
	}
	// Any remaining mapping with samples (e.g. EIM below medium confidence):
	// PDF, the conservative class.
	return CatPDF
}

// openMapping reports whether the traits describe an endpoint-independent
// mapping usable as a single public candidate.
func openMapping(t protocol.Traits) bool {
	return t.NoNAT == protocol.TriTrue ||
		(t.Mapping == protocol.MapEIM && t.MappingConf >= protocol.ConfMedium)
}

// opensBirthday reports whether a side's traits admit a birthday spray round: a
// side whose mapping or filtering is Unknown never opens birthday — an unknown
// conclusion must not justify large-scale spraying.
func opensBirthday(t protocol.Traits) bool {
	return t.Mapping != protocol.MapUnknown && t.Filtering != protocol.FiltUnknown
}

// Pair-class names (also the RoundPlan.variant prefix and
// plan.pair_class). They match the wire name syntax [a-z][a-z0-9_]{0,63}.
const (
	PairEasy    = "easy"
	PairOpenEDM = "open_x_edm"
	PairPDFSeq  = "pdf_x_seq"
	PairPDFRnd  = "pdf_x_rnd"
	PairSeqSeq  = "seq_x_seq"
	PairSeqRnd  = "seq_x_rnd"
	PairRndRnd  = "rnd_x_rnd"
	// PairPDFPres and PairPresPres are pdf_x_rnd and rnd_x_rnd where the
	// random side — both, in the second — keeps a fresh socket's local port
	// for its first mapping: fresh sockets replace the birthday
	// (freshPairClass).
	PairPDFPres  = "pdf_x_pres"
	PairPresPres = "pres_x_pres"
	PairV6Direct = "v6_direct"
	PairNoCommon = "" // no shared workable family
)

// PairClass names the ladder for two categories. The two arguments are
// order-independent. It returns "" when either side has no worker.
func PairClass(a, b Category) string {
	if a == CatNone || b == CatNone {
		return PairNoCommon
	}
	lo, hi := a, b
	if hi.rank() < lo.rank() {
		lo, hi = hi, lo
	}
	switch {
	case hi.rank() <= CatPDF.rank(): // both OPEN/PDF
		return PairEasy
	case lo == CatOpen: // OPEN x {SEQ,RND}
		return PairOpenEDM
	case lo == CatPDF && hi == CatSEQ:
		return PairPDFSeq
	case lo == CatPDF && hi == CatRND:
		return PairPDFRnd
	case lo == CatSEQ && hi == CatSEQ:
		return PairSeqSeq
	case lo == CatSEQ && hi == CatRND:
		return PairSeqRnd
	default: // RND x RND
		return PairRndRnd
	}
}
