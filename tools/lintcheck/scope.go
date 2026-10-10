package main

import (
	"go/ast"
	"go/token"
)

// scope is a lexical block of local declarations. The package and file
// blocks are not represented: a name not found in any scope refers to a
// package-level declaration or an import.
type scope struct {
	parent *scope
	names  map[string]bool
}

func newScope(parent *scope) *scope { return &scope{parent: parent} }

func (s *scope) declare(name string) {
	if name == "" || name == "_" {
		return
	}
	if s.names == nil {
		s.names = map[string]bool{}
	}
	s.names[name] = true
}

// local reports whether name is declared in s or an enclosing local scope.
func (s *scope) local(name string) bool {
	for ; s != nil; s = s.parent {
		if s.names[name] {
			return true
		}
	}
	return false
}

func (s *scope) declareFields(lists ...*ast.FieldList) {
	for _, l := range lists {
		if l == nil {
			continue
		}
		for _, f := range l.List {
			for _, n := range f.Names {
				s.declare(n.Name)
			}
		}
	}
}

// walker visits every node of executable code — function bodies and
// package-level variable declarations — together with the local scope it
// appears in. Declarations take effect where Go says they do: after the
// declaring statement, and for := after its right-hand side. Function
// signatures and type declarations are not visited.
type walker struct {
	visit func(n ast.Node, sc *scope)
}

func (w *walker) funcDecl(fd *ast.FuncDecl) {
	sc := newScope(nil)
	sc.declareFields(fd.Recv, fd.Type.TypeParams, fd.Type.Params, fd.Type.Results)
	if fd.Body != nil {
		w.stmts(fd.Body.List, sc)
	}
}

func (w *walker) valueSpec(vs *ast.ValueSpec, sc *scope) {
	w.expr(vs.Type, sc)
	for _, v := range vs.Values {
		w.expr(v, sc)
	}
}

func (w *walker) stmts(list []ast.Stmt, sc *scope) {
	for _, s := range list {
		w.stmt(s, sc)
	}
}

func (w *walker) stmt(s ast.Stmt, sc *scope) {
	if s == nil {
		return
	}
	w.visit(s, sc)
	switch s := s.(type) {
	case *ast.BlockStmt:
		w.stmts(s.List, newScope(sc))
	case *ast.IfStmt:
		in := newScope(sc)
		w.stmt(s.Init, in)
		w.expr(s.Cond, in)
		w.stmt(s.Body, in)
		w.stmt(s.Else, in)
	case *ast.ForStmt:
		in := newScope(sc)
		w.stmt(s.Init, in)
		w.expr(s.Cond, in)
		w.stmt(s.Post, in)
		w.stmt(s.Body, in)
	case *ast.RangeStmt:
		w.expr(s.X, sc)
		in := newScope(sc)
		if s.Tok == token.DEFINE {
			declareIdent(in, s.Key)
			declareIdent(in, s.Value)
		} else {
			w.expr(s.Key, in)
			w.expr(s.Value, in)
		}
		w.stmt(s.Body, in)
	case *ast.SwitchStmt:
		in := newScope(sc)
		w.stmt(s.Init, in)
		w.expr(s.Tag, in)
		for _, c := range s.Body.List {
			cc := c.(*ast.CaseClause)
			cs := newScope(in)
			w.exprs(cc.List, cs)
			w.stmts(cc.Body, cs)
		}
	case *ast.TypeSwitchStmt:
		in := newScope(sc)
		w.stmt(s.Init, in)
		bound := ""
		switch a := s.Assign.(type) {
		case *ast.AssignStmt: // x := y.(type)
			w.exprs(a.Rhs, in)
			if id, ok := a.Lhs[0].(*ast.Ident); ok {
				bound = id.Name
			}
		case *ast.ExprStmt:
			w.expr(a.X, in)
		}
		for _, c := range s.Body.List {
			cc := c.(*ast.CaseClause)
			cs := newScope(in)
			cs.declare(bound)
			w.stmts(cc.Body, cs)
		}
	case *ast.SelectStmt:
		for _, c := range s.Body.List {
			cc := c.(*ast.CommClause)
			cs := newScope(sc)
			w.stmt(cc.Comm, cs)
			w.stmts(cc.Body, cs)
		}
	case *ast.LabeledStmt:
		w.stmt(s.Stmt, sc)
	case *ast.AssignStmt:
		w.exprs(s.Rhs, sc)
		if s.Tok == token.DEFINE {
			for _, l := range s.Lhs {
				declareIdent(sc, l)
			}
		} else {
			w.exprs(s.Lhs, sc)
		}
	case *ast.DeclStmt:
		gd, ok := s.Decl.(*ast.GenDecl)
		if !ok {
			return
		}
		for _, spec := range gd.Specs {
			switch spec := spec.(type) {
			case *ast.ValueSpec:
				w.valueSpec(spec, sc)
				for _, n := range spec.Names {
					sc.declare(n.Name)
				}
			case *ast.TypeSpec:
				sc.declare(spec.Name.Name)
			}
		}
	case *ast.ExprStmt:
		w.expr(s.X, sc)
	case *ast.SendStmt:
		w.expr(s.Chan, sc)
		w.expr(s.Value, sc)
	case *ast.IncDecStmt:
		w.expr(s.X, sc)
	case *ast.GoStmt:
		w.expr(s.Call, sc)
	case *ast.DeferStmt:
		w.expr(s.Call, sc)
	case *ast.ReturnStmt:
		w.exprs(s.Results, sc)
	}
}

func declareIdent(sc *scope, e ast.Expr) {
	if id, ok := e.(*ast.Ident); ok {
		sc.declare(id.Name)
	}
}

func (w *walker) exprs(list []ast.Expr, sc *scope) {
	for _, e := range list {
		w.expr(e, sc)
	}
}

// expr visits e and its subexpressions; a function literal opens a new scope
// holding its parameters.
func (w *walker) expr(e ast.Expr, sc *scope) {
	if e == nil {
		return
	}
	ast.Inspect(e, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		w.visit(n, sc)
		if fl, ok := n.(*ast.FuncLit); ok {
			in := newScope(sc)
			in.declareFields(fl.Type.TypeParams, fl.Type.Params, fl.Type.Results)
			w.stmts(fl.Body.List, in)
			return false
		}
		return true
	})
}
