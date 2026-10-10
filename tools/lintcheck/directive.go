package main

import (
	"go/ast"
	"go/token"
	"strings"
)

const directivePrefix = "//holepunch:"

// Directive names.
const (
	// dirCallback marks user code: a function or method that calls user code,
	// a func-typed struct field holding a user callback, or an interface
	// method implemented by users.
	dirCallback = "callback"
	// dirNetImpl marks a function of the OS network implementation, the only
	// place package net may be used directly.
	dirNetImpl = "netimpl"
)

// netImplPackages are the packages (module-relative) allowed to contain
// //holepunch:netimpl functions: the root package's SystemNetwork and
// natprobe's default Listen.
func netImplPackages() []string { return []string{"", "natprobe"} }

// callbacks are the names annotated with //holepunch:callback.
type callbacks struct {
	exported map[string]bool          // fields, interface methods and methods; matched module-wide
	local    map[*pkg]map[string]bool // unexported ones, matched only in their package
	funcs    map[string]bool          // package-level functions as "importpath.Name"
}

func newCallbacks() callbacks {
	return callbacks{exported: map[string]bool{}, local: map[*pkg]map[string]bool{}, funcs: map[string]bool{}}
}

// member reports whether name is an annotated field, interface method or
// method visible from package p.
func (cb callbacks) member(p *pkg, name string) bool {
	if token.IsExported(name) {
		return cb.exported[name]
	}
	return cb.local[p][name]
}

func (cb callbacks) addMember(p *pkg, name string) {
	if token.IsExported(name) {
		cb.exported[name] = true
		return
	}
	if cb.local[p] == nil {
		cb.local[p] = map[string]bool{}
	}
	cb.local[p][name] = true
}

// directives validates the //holepunch: directives of p's production files,
// reporting problems when report is set, and records the valid ones.
func (c *checker) directives(p *pkg, report bool) {
	for _, f := range p.files {
		funcs := map[*ast.CommentGroup]*ast.FuncDecl{}
		members := map[*ast.CommentGroup][]*ast.Ident{} // func-typed struct fields and interface methods
		ast.Inspect(f.ast, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncDecl:
				if n.Doc != nil {
					funcs[n.Doc] = n
				}
			case *ast.StructType:
				for _, fld := range n.Fields.List {
					if _, ok := ast.Unparen(fld.Type).(*ast.FuncType); ok && len(fld.Names) > 0 {
						addGroups(members, fld)
					}
				}
			case *ast.InterfaceType:
				for _, fld := range n.Methods.List {
					if len(fld.Names) > 0 {
						addGroups(members, fld)
					}
				}
			}
			return true
		})
		for _, g := range f.ast.Comments {
			for _, cm := range g.List {
				name, rest, ok := parseDirective(cm.Text)
				if !ok {
					continue
				}
				msg := ""
				switch {
				case name != dirCallback && name != dirNetImpl:
					msg = "unknown directive " + directivePrefix + name + " (known: callback, netimpl)"
				case rest != "":
					msg = directivePrefix + name + " takes no arguments"
				case name == dirCallback:
					msg = c.registerCallback(p, funcs[g], members[g])
				case name == dirNetImpl:
					msg = c.registerNetImpl(p, funcs[g])
				}
				if msg != "" && report {
					c.report(cm.Pos(), ruleDirective, "%s", msg)
				}
			}
		}
	}
}

func addGroups(m map[*ast.CommentGroup][]*ast.Ident, fld *ast.Field) {
	for _, g := range []*ast.CommentGroup{fld.Doc, fld.Comment} {
		if g != nil {
			m[g] = append(m[g], fld.Names...)
		}
	}
}

// parseDirective splits a //holepunch:name comment. rest is any text after
// the name other than a trailing "// ..." comment.
func parseDirective(text string) (name, rest string, ok bool) {
	body, ok := strings.CutPrefix(text, directivePrefix)
	if !ok {
		return "", "", false
	}
	i := strings.IndexAny(body, " \t")
	if i < 0 {
		return body, "", true
	}
	name, rest = body[:i], strings.TrimSpace(body[i:])
	if strings.HasPrefix(rest, "//") {
		rest = ""
	}
	return name, rest, true
}

func (c *checker) registerCallback(p *pkg, fd *ast.FuncDecl, members []*ast.Ident) string {
	switch {
	case fd != nil && fd.Recv == nil:
		c.callbacks.funcs[p.path+"."+fd.Name.Name] = true
	case fd != nil:
		c.callbacks.addMember(p, fd.Name.Name)
	case len(members) > 0:
		for _, id := range members {
			c.callbacks.addMember(p, id.Name)
		}
	default:
		return directivePrefix + dirCallback + " must annotate a function, a func-typed struct field or an interface method"
	}
	return ""
}

func (c *checker) registerNetImpl(p *pkg, fd *ast.FuncDecl) string {
	if fd == nil {
		return directivePrefix + dirNetImpl + " must be in the doc comment of a function"
	}
	for _, allowed := range netImplPackages() {
		if p.rel == allowed {
			c.netimpl[fd] = true
			return ""
		}
	}
	return directivePrefix + dirNetImpl + " is only allowed in the root package and natprobe"
}
