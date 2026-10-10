package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"path/filepath"
	"sort"
)

// Rule names, as printed in diagnostics and used by fixture markers.
const (
	ruleNoBareGo      = "nobarego"
	ruleNoGlobalState = "noglobalstate"
	ruleNoDirectNet   = "nodirectnet"
	ruleNoSleep       = "nosleep"
	ruleCallbackLock  = "callbacklock"
	ruleDirective     = "directive"
)

// allRules lists every rule; the fixture test requires a marker for each.
func allRules() []string {
	return []string{ruleNoBareGo, ruleNoGlobalState, ruleNoDirectNet, ruleNoSleep, ruleCallbackLock, ruleDirective}
}

type diagnostic struct {
	pos  token.Position
	rule string
	msg  string
}

// checker holds the module-wide facts gathered before the per-file rules run
// and the diagnostics of the packages being reported.
type checker struct {
	mod       *module
	callbacks callbacks
	netimpl   map[*ast.FuncDecl]bool // functions with a valid //holepunch:netimpl
	writes    map[varKey]token.Pos   // first run-time write of each package-level variable
	diags     []diagnostic
}

// check runs every rule on targets. Directives and writes to package-level
// variables are collected from the whole module first, so that a callback
// declared, or a variable written, in a package that is not being checked is
// still taken into account.
func check(mod *module, targets []*pkg) []diagnostic {
	c := &checker{
		mod:       mod,
		callbacks: newCallbacks(),
		netimpl:   map[*ast.FuncDecl]bool{},
		writes:    map[varKey]token.Pos{},
	}
	reported := map[*pkg]bool{}
	for _, p := range targets {
		reported[p] = true
	}
	for _, p := range mod.pkgs {
		c.directives(p, reported[p])
	}
	c.collectWrites()
	for _, p := range targets {
		for _, f := range p.files {
			ps := &pass{c: c, p: p, f: f}
			ps.run()
		}
	}
	sort.Slice(c.diags, func(i, j int) bool {
		a, b := c.diags[i], c.diags[j]
		if a.pos.Filename != b.pos.Filename {
			return a.pos.Filename < b.pos.Filename
		}
		if a.pos.Line != b.pos.Line {
			return a.pos.Line < b.pos.Line
		}
		if a.pos.Column != b.pos.Column {
			return a.pos.Column < b.pos.Column
		}
		return a.rule < b.rule
	})
	return c.diags
}

func (c *checker) report(pos token.Pos, rule, format string, args ...any) {
	c.diags = append(c.diags, diagnostic{pos: c.mod.fset.Position(pos), rule: rule, msg: fmt.Sprintf(format, args...)})
}

// where formats pos as a module-relative "file:line" for messages.
func (c *checker) where(pos token.Pos) string {
	p := c.mod.fset.Position(pos)
	name := p.Filename
	if rel, err := filepath.Rel(c.mod.root, name); err == nil {
		name = filepath.ToSlash(rel)
	}
	return fmt.Sprintf("%s:%d", name, p.Line)
}

// pass checks one production file. fn is the function declaration being
// walked, nil for package-level variable declarations.
type pass struct {
	c  *checker
	p  *pkg
	f  *file
	fn *ast.FuncDecl
}

func (ps *pass) run() {
	w := &walker{visit: ps.visit}
	for _, d := range ps.f.ast.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			ps.fn = d
			w.funcDecl(d)
			ps.callbackLock(d)
		case *ast.GenDecl:
			if d.Tok != token.VAR {
				continue
			}
			ps.fn = nil
			for _, s := range d.Specs {
				vs := s.(*ast.ValueSpec)
				ps.globalDecl(vs)
				w.valueSpec(vs, newScope(nil))
			}
		}
	}
}

// visit dispatches the scope-aware rules.
func (ps *pass) visit(n ast.Node, sc *scope) {
	switch n := n.(type) {
	case *ast.GoStmt:
		ps.goStmt(n)
	case *ast.SelectorExpr:
		id, ok := n.X.(*ast.Ident)
		if !ok || sc.local(id.Name) {
			return
		}
		switch ps.f.imports[id.Name] {
		case "time":
			ps.timeSelector(n)
		case "net":
			ps.netSelector(n)
		}
	}
}
