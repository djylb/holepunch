package portmapper

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/djylb/holepunch/protocol"
)

// portMapper is holepunch.PortMapper, declared here
// because this package must not import the client runtime. *Mapper satisfies
// it with no glue.
type portMapper interface {
	Map(ctx context.Context, conn net.PacketConn, policy protocol.PortMappingPolicy) (info protocol.PortMappingInfo, release func() error, err error)
}

var _ portMapper = (*Mapper)(nil)

// TestExportedAPI pins the exported surface to its seven symbols.
func TestExportedAPI(t *testing.T) {
	want := []string{"Config", "ErrNoGateway", "ErrUnsupported", "Mapper", "Mapper.Close", "Mapper.Map", "New"}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var got []string
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
				got = append(got, name)
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						if s.Name.IsExported() {
							got = append(got, s.Name.Name)
						}
					case *ast.ValueSpec:
						for _, n := range s.Names {
							if n.IsExported() {
								got = append(got, n.Name)
							}
						}
					}
				}
			}
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("exported API = %v, want %v", got, want)
	}
}
