package udpwire

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strings"
	"testing"
)

// TestExportedAPI pins the exported surface to its final list: 39 constants
// and 30 other
// symbols (8 types, 10 functions, 12 methods), within the ≤ 42 / ≤ 30 budget.
func TestExportedAPI(t *testing.T) {
	wantConsts := []string{
		"B0Max", "B0Min", "DefaultResidualWindow", "ErrAuth", "ErrForeign", "ErrPayload", "ErrRate",
		"ErrReplay", "ErrRole", "ErrRoute", "ErrShort", "HeaderSize", "MaxPlaintext", "MaxWrapped", "MinAckPlaintext",
		"MinExtraPlaintext", "MinPeerPacket", "MinProbePacket", "NoCand", "NonceSize", "OK",
		"PeerOuterSize", "ProbeOuterSize", "RoleInitiator", "RoleResponder", "RoleServer", "RouteSize",
		"TAccept", "THairpin", "THandoverAck", "TNominate", "TProbe", "TProbeAck", "TProbeAlt",
		"TProbeExtra", "TPunch", "TReady", "TSuccess", "TagSize",
	}
	wantOthers := []string{
		"Codec", "DecodeError", "Header", "PadPolicy", "Role", "SeqWindow", "TLVs", "Type",
		"DropResidual", "NewCodec", "NewPadPolicy", "PacerSeed", "Precheck", "ReplyLengths", "SpraySeed", "UnmaskRoute",
		"Unwrap", "Wrapped",
		"Codec.BindPeers", "Codec.CheckRole", "Codec.NextSeq", "Codec.Now", "Codec.Open", "Codec.OpenProbe",
		"Codec.Peers", "Codec.Role", "Codec.Seal", "Codec.Wrap", "DecodeError.String", "SeqWindow.Accept",
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var consts, others []string
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if !d.Name.IsExported() {
					continue
				}
				name := d.Name.Name
				if d.Recv != nil {
					recv := d.Recv.List[0].Type
					if star, ok := recv.(*ast.StarExpr); ok {
						recv = star.X
					}
					typ := recv.(*ast.Ident)
					if !typ.IsExported() {
						continue // methods of unexported types are not API
					}
					name = typ.Name + "." + name
				}
				others = append(others, name)
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						if s.Name.IsExported() {
							others = append(others, s.Name.Name)
						}
					case *ast.ValueSpec:
						for _, n := range s.Names {
							if !n.IsExported() {
								continue
							}
							if d.Tok == token.CONST {
								consts = append(consts, n.Name)
							} else {
								others = append(others, n.Name)
							}
						}
					}
				}
			}
		}
	}
	slices.Sort(consts)
	slices.Sort(others)
	slices.Sort(wantConsts)
	slices.Sort(wantOthers)
	if !slices.Equal(consts, wantConsts) {
		t.Errorf("exported constants (%d):\n%v\nwant (%d):\n%v", len(consts), consts, len(wantConsts), wantConsts)
	}
	if !slices.Equal(others, wantOthers) {
		t.Errorf("exported non-constants (%d):\n%v\nwant (%d):\n%v", len(others), others, len(wantOthers), wantOthers)
	}
}
