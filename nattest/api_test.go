package nattest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strings"
	"testing"
)

// exportedAPI is the complete public surface of the package. A change to it
// is a deliberate API decision and must update this
// list.
var exportedAPI = []string{
	// types
	"DropStats", "ExitPolicy", "Filtering", "Host", "HostStats", "IPv6Config", "IPv6Mode",
	"LinkConfig", "Mapping", "MappingInfo", "NAT", "NATConfig", "NATStats", "NetStats",
	"Classifier", "Network", "Option", "PipeConfig", "PipeConn", "PortAlloc", "Route", "ScanDefense", "SocketStats",
	// constants
	"ADF", "ADM", "APDF", "APDM", "EIF", "EIM", "Identity", "NAT66", "NPTv6", "NoNAT",
	"NoTimeout", "Open", "PerDestIP", "PerSourcePort", "Preserve", "PreserveThenRandom", "PreserveThenSequential",
	"Random", "RoundRobin", "Sequential", "SingleExit",
	// functions
	"CGNAT", "FullCone", "IsSTUN", "NewNetwork", "Pool", "PortRestricted", "PublicFW", "PublicOpen",
	"RestrictedCone", "SymmetricPreserveRandom", "SymmetricRandom", "SymmetricSeq",
	"WithClock", "WithCoreHops", "WithCoreLink", "WithEventLog", "WithSeed",
	// methods
	"DropStats.Total", "ExitPolicy.String", "Filtering.String", "IPv6Mode.String",
	"Mapping.String", "PortAlloc.String",
	"Host.Addrs", "Host.Crash", "Host.FailBinds", "Host.FailWrites", "Host.InterfaceAddrs",
	"Host.Listen", "Host.ListenPacket", "Host.LookupNetIP", "Host.MarkHandover",
	"Host.OpenSockets", "Host.OutboundAddr", "Host.Stats",
	"NAT.Blackhole", "NAT.DropUpstream", "NAT.ExpireAll", "NAT.ExternalIPs", "NAT.Host", "NAT.Mappings", "NAT.NAT",
	"NAT.Rebind", "NAT.SetLink", "NAT.Stats",
	"Network.Close", "Network.Dump", "Network.NAT", "Network.Pipe", "Network.PublicHost",
	"Network.SetDNS", "Network.Stats",
	"PipeConn.Blackhole", "PipeConn.Close", "PipeConn.Cut", "PipeConn.LocalAddr", "PipeConn.Read",
	"PipeConn.RemoteAddr", "PipeConn.SetDeadline", "PipeConn.SetDelay", "PipeConn.SetReadDeadline",
	"PipeConn.SetWriteDeadline", "PipeConn.Write",
}

func TestExportedAPI(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			got = append(got, exportedNames(t, fset, d)...)
		}
	}
	slices.Sort(got)
	want := slices.Sorted(slices.Values(exportedAPI))
	if !slices.Equal(got, want) {
		t.Fatalf("exported API changed:\n got  %v\n want %v", got, want)
	}
}

// exportedNames returns the exported names d declares and checks that each
// has a doc comment (a grouped constant may share its group's comment or
// carry a line comment).
func exportedNames(t *testing.T, fset *token.FileSet, d ast.Decl) []string {
	var out []string
	switch d := d.(type) {
	case *ast.FuncDecl:
		if !d.Name.IsExported() {
			return nil
		}
		name := d.Name.Name
		if d.Recv != nil {
			typ := d.Recv.List[0].Type
			if s, ok := typ.(*ast.StarExpr); ok {
				typ = s.X
			}
			recv := typ.(*ast.Ident).Name
			if !ast.IsExported(recv) {
				return nil
			}
			name = recv + "." + name
		}
		if d.Doc == nil {
			t.Errorf("%s: %s has no doc comment", fset.Position(d.Pos()), name)
		}
		out = append(out, name)
	case *ast.GenDecl:
		for _, s := range d.Specs {
			switch s := s.(type) {
			case *ast.TypeSpec:
				if s.Name.IsExported() {
					if d.Doc == nil && s.Doc == nil {
						t.Errorf("%s: type %s has no doc comment", fset.Position(s.Pos()), s.Name.Name)
					}
					out = append(out, s.Name.Name)
				}
			case *ast.ValueSpec:
				for _, id := range s.Names {
					if id.IsExported() {
						if d.Doc == nil && s.Doc == nil && s.Comment == nil {
							t.Errorf("%s: %s has no doc comment", fset.Position(id.Pos()), id.Name)
						}
						out = append(out, id.Name)
					}
				}
			}
		}
	}
	return out
}
