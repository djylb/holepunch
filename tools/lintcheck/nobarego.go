package main

import "go/ast"

// lifePackage is the only package whose (*Group).Go may contain a go
// statement.
const lifePackage = "internal/life"

// goStmt implements nobarego.
func (ps *pass) goStmt(g *ast.GoStmt) {
	fn := ps.fn
	if ps.p.rel == lifePackage && fn != nil && fn.Name.Name == "Go" && receiverType(fn) == "Group" {
		return
	}
	ps.c.report(g.Go, ruleNoBareGo, "go statement outside (*life.Group).Go; start goroutines with life.Group.Go")
}

// receiverType returns the base type name of fd's receiver, "" for a
// function.
func receiverType(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return ""
	}
	t := fd.Recv.List[0].Type
	for {
		switch x := t.(type) {
		case *ast.StarExpr:
			t = x.X
		case *ast.ParenExpr:
			t = x.X
		case *ast.IndexExpr: // generic receiver T[P]
			t = x.X
		case *ast.IndexListExpr:
			t = x.X
		case *ast.Ident:
			return x.Name
		default:
			return ""
		}
	}
}
