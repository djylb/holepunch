package main

import (
	"go/ast"
	"go/token"
	"strings"
)

// varKey names a package-level variable by import path and name.
type varKey struct{ pkg, name string }

// collectWrites records the first run-time write to every package-level
// variable of the module, found anywhere in it: production files, test files
// (a test that swaps a package variable proves the variable is mutable
// state) and other packages (pkg.Var = x). A write is an assignment, ++/--,
// a range assignment, delete, clear, copy or append on the variable, or
// taking its address — an address lets anyone write later. Function init and
// package-level initialisers are initialisation, not run time.
func (c *checker) collectWrites() {
	for _, p := range c.mod.pkgs {
		own := ""
		if len(p.files) > 0 {
			own = p.files[0].ast.Name.Name
		}
		for _, f := range p.files {
			c.fileWrites(p, f, true)
		}
		for _, f := range p.tests {
			// An external test package (package x_test) reaches x only
			// through its import.
			c.fileWrites(p, f, f.ast.Name.Name == own)
		}
	}
}

func (c *checker) fileWrites(p *pkg, f *file, samePackage bool) {
	mark := func(e ast.Expr, pos token.Pos, sc *scope) {
		id, sel := rootOf(e)
		if id == nil || sc.local(id.Name) {
			return
		}
		key := varKey{}
		switch imp, isImport := f.imports[id.Name]; {
		case isImport && sel != nil:
			key = varKey{imp, sel.Sel.Name}
		case !isImport && samePackage && p.vars[id.Name]:
			key = varKey{p.path, id.Name}
		default:
			return
		}
		if _, seen := c.writes[key]; !seen {
			c.writes[key] = pos
		}
	}
	w := &walker{visit: func(n ast.Node, s *scope) {
		switch n := n.(type) {
		case *ast.AssignStmt:
			if n.Tok != token.DEFINE {
				for _, l := range n.Lhs {
					mark(l, l.Pos(), s)
				}
			}
		case *ast.IncDecStmt:
			mark(n.X, n.Pos(), s)
		case *ast.RangeStmt:
			if n.Tok == token.ASSIGN {
				for _, e := range []ast.Expr{n.Key, n.Value} {
					if e != nil {
						mark(e, e.Pos(), s)
					}
				}
			}
		case *ast.UnaryExpr:
			if n.Op == token.AND {
				mark(n.X, n.Pos(), s)
			}
		case *ast.CallExpr:
			if id, ok := ast.Unparen(n.Fun).(*ast.Ident); ok && len(n.Args) > 0 && !s.local(id.Name) && !p.decls[id.Name] {
				switch id.Name {
				case "delete", "clear", "copy", "append":
					mark(n.Args[0], n.Pos(), s)
				}
			}
		}
	}}
	for _, d := range f.ast.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && !(fd.Recv == nil && fd.Name.Name == "init") {
			w.funcDecl(fd)
		}
	}
}

// rootOf strips index, slice, dereference, parentheses and field selection
// from e and returns the identifier it starts from. When that identifier is
// the X of a selector (possibly a package qualifier), the selector is
// returned too.
func rootOf(e ast.Expr) (*ast.Ident, *ast.SelectorExpr) {
	for {
		switch x := e.(type) {
		case *ast.Ident:
			return x, nil
		case *ast.ParenExpr:
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.IndexListExpr:
			e = x.X
		case *ast.SliceExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok {
				return id, x
			}
			e = x.X
		default:
			return nil, nil
		}
	}
}

// globalDecl implements noglobalstate for one package-level var spec.
func (ps *pass) globalDecl(vs *ast.ValueSpec) {
	for i, id := range vs.Names {
		if id.Name == "_" {
			continue
		}
		var value ast.Expr
		if len(vs.Values) == len(vs.Names) {
			value = vs.Values[i]
		}
		if what := ps.mutableKind(vs.Type, value, id.Name); what != "" {
			ps.c.report(id.Pos(), ruleNoGlobalState, "package-level var %s holds %s; keep mutable state in an instance", id.Name, what)
			continue
		}
		if pos, ok := ps.c.writes[varKey{ps.p.path, id.Name}]; ok {
			ps.c.report(id.Pos(), ruleNoGlobalState, "package-level var %s is mutable (written or address taken at %s); keep mutable state in an instance", id.Name, ps.c.where(pos))
		}
	}
}

// mutableKind describes why a declaration can only be mutable state, or
// returns "": a sync or sync/atomic type other than sync.Pool, a channel, or
// a pointer (&T{} or new(T)) except to a sync.Pool or for a sentinel error.
func (ps *pass) mutableKind(typ, value ast.Expr, name string) string {
	if what := ps.stateType(typ); what != "" {
		return what
	}
	sentinel := strings.HasPrefix(name, "Err") || strings.HasPrefix(name, "err")
	switch v := ast.Unparen(value).(type) {
	case *ast.CompositeLit:
		return ps.stateType(v.Type)
	case *ast.UnaryExpr:
		if v.Op != token.AND {
			return ""
		}
		cl, ok := ast.Unparen(v.X).(*ast.CompositeLit)
		if !ok {
			return "the address of another variable"
		}
		if what := ps.stateType(cl.Type); what != "" {
			return what
		}
		if !sentinel && !ps.isPool(cl.Type) {
			return "a pointer to a shared value"
		}
	case *ast.CallExpr:
		id, ok := ast.Unparen(v.Fun).(*ast.Ident)
		if !ok || ps.p.decls[id.Name] || len(v.Args) == 0 {
			return ""
		}
		switch id.Name {
		case "make":
			return ps.stateType(v.Args[0])
		case "new":
			if what := ps.stateType(v.Args[0]); what != "" {
				return what
			}
			if !sentinel && !ps.isPool(v.Args[0]) {
				return "a pointer to a shared value"
			}
		}
	}
	return ""
}

// stateType names t when it is a channel or a sync / sync/atomic type other
// than sync.Pool, looking through pointers and arrays.
func (ps *pass) stateType(t ast.Expr) string {
	t = baseType(t)
	if _, ok := t.(*ast.ChanType); ok {
		return "a channel"
	}
	sel, ok := t.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	switch ps.f.imports[id.Name] {
	case "sync":
		if sel.Sel.Name != "Pool" && sel.Sel.Name != "Locker" {
			return "a sync." + sel.Sel.Name
		}
	case "sync/atomic":
		return "an atomic." + sel.Sel.Name
	}
	return ""
}

// baseType strips parentheses, pointers, arrays and type arguments.
func baseType(t ast.Expr) ast.Expr {
	for {
		switch x := t.(type) {
		case *ast.ParenExpr:
			t = x.X
		case *ast.StarExpr:
			t = x.X
		case *ast.ArrayType:
			t = x.Elt
		case *ast.IndexExpr: // atomic.Pointer[T]
			t = x.X
		default:
			return t
		}
	}
}

func (ps *pass) isPool(t ast.Expr) bool {
	sel, ok := ast.Unparen(t).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && ps.f.imports[id.Name] == "sync" && sel.Sel.Name == "Pool"
}
