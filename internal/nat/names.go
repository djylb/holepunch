package nat

import (
	"fmt"
	"math/bits"
	"strconv"

	"github.com/djylb/holepunch/protocol"
)

// DisplayName is a name for people (web pages, logs); no library decision
// may depend on it. "?" marks a mapping conclusion
// below High. Suffixes: "+CGNAT", "+hairpin" or "-hairpin", "+pres" (port
// preserving); IPv6 names start with "v6:".
func DisplayName(t protocol.Traits) string {
	q := ""
	if t.MappingConf < protocol.ConfHigh {
		q = "?"
	}
	var name string
	switch {
	case t.Samples == 0:
		name = "Unknown(no-probe)"
	case t.NoNAT == protocol.TriTrue && t.Filtering == protocol.FiltEIF:
		name = "Public"
	case t.NoNAT == protocol.TriTrue:
		name = "Public+Firewall"
	case t.MultiExit:
		name = "MultiExit" + q
	case t.Mapping == protocol.MapAPDM && t.PortAlloc == protocol.AllocSequential:
		name = fmt.Sprintf("Symmetric(step %+d)%s", t.PortStep, q)
	case t.Mapping == protocol.MapAPDM && t.PortAlloc == protocol.AllocPool:
		name = fmt.Sprintf("Symmetric(pool %d)%s", poolSize(t), q)
	case t.Mapping == protocol.MapAPDM && t.PortAlloc == protocol.AllocPreserveFresh:
		name = "Symmetric(fresh-preserving)" + q
	case t.Mapping == protocol.MapAPDM:
		name = "Symmetric(random)" + q
	case t.Mapping == protocol.MapADM:
		name = "AddressDependent" + q
	case t.Mapping == protocol.MapEIM:
		name = coneName(t.Filtering) + q
	default:
		name = fmt.Sprintf("Unknown(%d samples)", t.Samples)
	}
	if t.CGNAT == protocol.TriTrue {
		name += "+CGNAT"
	}
	switch t.Hairpin {
	case protocol.TriTrue:
		name += "+hairpin"
	case protocol.TriFalse:
		name += "-hairpin"
	case protocol.TriUnknown:
		// Untested hairpinning adds nothing to the name.
	}
	if t.PortAlloc == protocol.AllocPreserving && t.NoNAT != protocol.TriTrue {
		name += "+pres"
	}
	if t.Family == protocol.FamilyUDP6 {
		name = "v6:" + name
	}
	return name
}

func coneName(f protocol.Filtering) string {
	switch f {
	case protocol.FiltEIF:
		return "FullCone"
	case protocol.FiltADF:
		return "RestrictedCone"
	case protocol.FiltPDF:
		return "PortRestrictedCone"
	case protocol.FiltNotPDF:
		return "Cone(EIF/ADF)"
	default: // FiltUnknown or out of range
		return "Cone(filter-untested)"
	}
}

// class is the coarse NAT class behind Fingerprint and ClassBits; each field
// indexes the token tables of Fingerprint.
type class struct {
	fam, mapping, filtering, alloc uint8
	param                          uint8 // sequential: step+64 (step clamped to ±64); pool: log2 of the block size
}

// Class field values.
const (
	famUnknown, famV4, famV6 = 0, 1, 2

	mapUnknown, mapNoNAT, mapMultiExit, mapEIM, mapADM, mapAPDM = 0, 1, 2, 3, 4, 5

	filtUnknown, filtEIF, filtADF, filtNotPDF, filtPDF = 0, 1, 2, 3, 4

	allocNone, allocUnknown, allocPres, allocSeq, allocPool, allocRandom, allocFresh = 0, 1, 2, 3, 4, 5, 6
)

func classOf(t protocol.Traits) class {
	var c class
	switch t.Family {
	case protocol.FamilyUDP4:
		c.fam = famV4
	case protocol.FamilyUDP6:
		c.fam = famV6
	default:
		c.fam = famUnknown
	}
	switch {
	case t.NoNAT == protocol.TriTrue:
		c.mapping = mapNoNAT
	case t.MultiExit:
		c.mapping = mapMultiExit
	case t.Mapping == protocol.MapEIM:
		c.mapping = mapEIM
	case t.Mapping == protocol.MapADM:
		c.mapping = mapADM
	case t.Mapping == protocol.MapAPDM:
		c.mapping = mapAPDM
	default:
		c.mapping = mapUnknown
	}
	switch t.Filtering {
	case protocol.FiltEIF:
		c.filtering = filtEIF
	case protocol.FiltADF:
		c.filtering = filtADF
	case protocol.FiltNotPDF:
		c.filtering = filtNotPDF
	case protocol.FiltPDF:
		c.filtering = filtPDF
	default:
		c.filtering = filtUnknown
	}
	if c.mapping == mapNoNAT {
		c.alloc = allocNone // without NAT the allocation is trivially preserving
		return c
	}
	switch t.PortAlloc {
	case protocol.AllocPreserving:
		c.alloc = allocPres
	case protocol.AllocSequential:
		c.alloc = allocSeq
		c.param = uint8(min(max(int(t.PortStep), -maxStep), maxStep) + maxStep)
	case protocol.AllocPool:
		c.alloc = allocPool
		c.param = uint8(bits.Len32(uint32(poolSize(t)) - 1))
	case protocol.AllocRandom:
		c.alloc = allocRandom
	case protocol.AllocPreserveFresh:
		c.alloc = allocFresh
	default:
		c.alloc = allocUnknown
	}
	return c
}

// poolSize is the estimated port block: the power of two covering
// PortRangeLo..PortRangeHi (at least 1).
func poolSize(t protocol.Traits) int {
	n := max(int(t.PortRangeHi)-int(t.PortRangeLo)+1, 1)
	return 1 << bits.Len32(uint32(n)-1)
}

// Fingerprint is the coarse NAT fingerprint for people and logs:
// "family|mapping|filtering|allocation", for example "v4|EIM|PDF|PRES",
// "v4|APDM|PDF|SEQ+1", "v4|APDM|PDF|POOL1024" and "v6|NONAT|PDF" (no NAT has
// no allocation part). Tokens: family v4 | v6 | v?; mapping NONAT |
// MULTIEXIT | EIM | ADM | APDM | UNK; filtering EIF | ADF | NOTPDF | PDF |
// UNK; allocation PRES | SEQ±d (d clamped to ±64) | POOL<block> | RAND |
// FRESH (a fresh socket keeps its port) | UNK.
func Fingerprint(t protocol.Traits) string {
	c := classOf(t)
	s := [...]string{"v?", "v4", "v6"}[c.fam] + "|" +
		[...]string{"UNK", "NONAT", "MULTIEXIT", "EIM", "ADM", "APDM"}[c.mapping] + "|" +
		[...]string{"UNK", "EIF", "ADF", "NOTPDF", "PDF"}[c.filtering]
	switch c.alloc {
	case allocNone:
		return s
	case allocSeq:
		return s + "|SEQ" + fmt.Sprintf("%+d", int(c.param)-maxStep)
	case allocPool:
		return s + "|POOL" + strconv.Itoa(1<<c.param)
	case allocPres:
		return s + "|PRES"
	case allocRandom:
		return s + "|RAND"
	case allocFresh:
		return s + "|FRESH"
	}
	return s + "|UNK"
}

// ClassBits is the fixed-width encoding of Fingerprint: equal fingerprints
// give equal bits and different fingerprints different bits. It feeds
// coord.StrategyKey. Layout from the least
// significant bit: 0–1 family, 2–4 mapping, 5–7 filtering, 8–10 allocation,
// 11–18 allocation parameter (sequential: step+64; pool: log2 of the block);
// the rest are zero.
func ClassBits(t protocol.Traits) uint32 {
	c := classOf(t)
	return uint32(c.fam) | uint32(c.mapping)<<2 | uint32(c.filtering)<<5 | uint32(c.alloc)<<8 | uint32(c.param)<<11
}
