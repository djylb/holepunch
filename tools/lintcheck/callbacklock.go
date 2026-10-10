package main

import (
	"go/ast"
	"go/token"
	"go/types"
	"sort"
)

// lockSet maps a held lock, keyed by the rendered receiver expression, to
// the position of the Lock call that took it.
type lockSet map[string]token.Pos

func (s lockSet) clone() lockSet {
	out := make(lockSet, len(s))
	for k, v := range s {
		out[k] = v
	}
	return out
}

// union merges the states of paths that reach the same point: a lock held
// on any of them may be held there.
func union(sets ...lockSet) lockSet {
	out := lockSet{}
	for _, s := range sets {
		for k, v := range s {
			if old, ok := out[k]; !ok || v < old {
				out[k] = v
			}
		}
	}
	return out
}

// jumpTarget is an enclosing loop, switch or select. break leaves it (and,
// for a loop, continue eventually does too); exits collects the lock states
// carried out that way.
type jumpTarget struct {
	label string
	loop  bool
	exits []lockSet
}

// lockFlow is the callbacklock analysis of one function body.
type lockFlow struct {
	ps      *pass
	targets []*jumpTarget
	label   string // label of the statement about to be analysed
}

// callbackLock implements callbacklock for one function declaration.
func (ps *pass) callbackLock(fd *ast.FuncDecl) {
	if fd.Body != nil {
		ps.lockBody(fd.Body, lockSet{})
	}
}

// lockBody analyses a function body starting with held; a function literal
// body has jump targets of its own.
func (ps *pass) lockBody(body *ast.BlockStmt, held lockSet) {
	lf := &lockFlow{ps: ps}
	lf.stmts(body.List, held)
}

// stmts analyses list starting with held. It returns the state at the end
// and whether no path falls through.
func (lf *lockFlow) stmts(list []ast.Stmt, held lockSet) (lockSet, bool) {
	for _, s := range list {
		var term bool
		held, term = lf.stmt(s, held)
		if term {
			return held, true
		}
	}
	return held, false
}

func (lf *lockFlow) stmt(s ast.Stmt, held lockSet) (lockSet, bool) {
	label := lf.label
	lf.label = ""
	switch s := s.(type) {
	case *ast.BlockStmt:
		return lf.stmts(s.List, held)
	case *ast.LabeledStmt:
		lf.label = s.Label.Name
		return lf.stmt(s.Stmt, held)
	case *ast.ExprStmt:
		lf.expr(s.X, held)
		if call, ok := s.X.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "panic" {
				return held, true
			}
		}
	case *ast.AssignStmt:
		lf.exprs(s.Rhs, held)
		lf.exprs(s.Lhs, held)
	case *ast.DeclStmt:
		lf.expr(s.Decl, held)
	case *ast.IncDecStmt:
		lf.expr(s.X, held)
	case *ast.SendStmt:
		lf.expr(s.Chan, held)
		lf.expr(s.Value, held)
	case *ast.ReturnStmt:
		lf.exprs(s.Results, held)
		return held, true
	case *ast.BranchStmt:
		return lf.branch(s, held)
	case *ast.GoStmt:
		lf.laterCall(s.Call, held)
	case *ast.DeferStmt:
		// A deferred Unlock keeps the lock held to the end of the function.
		lf.laterCall(s.Call, held)
	case *ast.IfStmt:
		h := held.clone()
		if s.Init != nil {
			h, _ = lf.stmt(s.Init, h)
		}
		lf.expr(s.Cond, h)
		thenOut, thenTerm := lf.stmts(s.Body.List, h.clone())
		elseOut, elseTerm := h, false
		if s.Else != nil {
			elseOut, elseTerm = lf.stmt(s.Else, h.clone())
		}
		return merge(h, []lockSet{thenOut, elseOut}, []bool{thenTerm, elseTerm}, nil)
	case *ast.ForStmt:
		h := held.clone()
		if s.Init != nil {
			h, _ = lf.stmt(s.Init, h)
		}
		lf.expr(s.Cond, h)
		t := lf.push(label, true)
		body, term := lf.stmts(s.Body.List, h.clone())
		if !term && s.Post != nil {
			body, _ = lf.stmt(s.Post, body)
		}
		lf.pop()
		return loopExit(t, h, body, term), false
	case *ast.RangeStmt:
		h := held.clone()
		lf.expr(s.X, h)
		t := lf.push(label, true)
		body, term := lf.stmts(s.Body.List, h.clone())
		lf.pop()
		return loopExit(t, h, body, term), false
	case *ast.SwitchStmt:
		h := held.clone()
		if s.Init != nil {
			h, _ = lf.stmt(s.Init, h)
		}
		lf.expr(s.Tag, h)
		return lf.clauses(label, s.Body, h, false)
	case *ast.TypeSwitchStmt:
		h := held.clone()
		if s.Init != nil {
			h, _ = lf.stmt(s.Init, h)
		}
		h, _ = lf.stmt(s.Assign, h)
		return lf.clauses(label, s.Body, h, false)
	case *ast.SelectStmt:
		return lf.clauses(label, s.Body, held.clone(), true)
	}
	return held, false
}

// branch handles break, continue, goto and fallthrough.
func (lf *lockFlow) branch(s *ast.BranchStmt, held lockSet) (lockSet, bool) {
	switch s.Tok {
	case token.BREAK, token.CONTINUE:
		for i := len(lf.targets) - 1; i >= 0; i-- {
			t := lf.targets[i]
			if s.Label != nil && t.label != s.Label.Name || s.Label == nil && s.Tok == token.CONTINUE && !t.loop {
				continue
			}
			t.exits = append(t.exits, held.clone())
			return held, true
		}
		return held, false
	case token.GOTO:
		// The state at the label is unknown; the path ends here.
		return held, true
	}
	return held, false // fallthrough: the clause's state reaches the switch exit
}

// loopExit is the state after a loop: it may run zero times, end its body
// normally or be left by break; continue leads back to the condition.
func loopExit(t *jumpTarget, entry, body lockSet, bodyTerm bool) lockSet {
	states := append(t.exits, entry)
	if !bodyTerm {
		states = append(states, body)
	}
	return union(states...)
}

func (lf *lockFlow) push(label string, loop bool) *jumpTarget {
	t := &jumpTarget{label: label, loop: loop}
	lf.targets = append(lf.targets, t)
	return t
}

func (lf *lockFlow) pop() { lf.targets = lf.targets[:len(lf.targets)-1] }

// merge joins the outcomes of alternative paths with the states carried out
// by break; entry is returned when no path reaches the end.
func merge(entry lockSet, outs []lockSet, terms []bool, exits []lockSet) (lockSet, bool) {
	live := exits
	for i, o := range outs {
		if !terms[i] {
			live = append(live, o)
		}
	}
	if len(live) == 0 {
		return entry, true
	}
	return union(live...), false
}

// clauses analyses the clauses of a switch or select. A switch without a
// default clause may run none of them; a select always runs one (and an
// empty select blocks forever).
func (lf *lockFlow) clauses(label string, body *ast.BlockStmt, h lockSet, isSelect bool) (lockSet, bool) {
	t := lf.push(label, false)
	var outs []lockSet
	var terms []bool
	hasDefault := false
	for _, st := range body.List {
		ch := h.clone()
		var list []ast.Stmt
		switch cl := st.(type) {
		case *ast.CaseClause:
			hasDefault = hasDefault || cl.List == nil
			lf.exprs(cl.List, ch)
			list = cl.Body
		case *ast.CommClause:
			if cl.Comm != nil {
				ch, _ = lf.stmt(cl.Comm, ch)
			}
			list = cl.Body
		}
		out, term := lf.stmts(list, ch)
		outs = append(outs, out)
		terms = append(terms, term)
	}
	lf.pop()
	if !isSelect && !hasDefault {
		outs = append(outs, h)
		terms = append(terms, false)
	}
	return merge(h, outs, terms, t.exits)
}

// laterCall handles go and defer: the function value and arguments are
// evaluated now, the call runs later under locks this analysis cannot know.
func (lf *lockFlow) laterCall(call *ast.CallExpr, held lockSet) {
	if fl, ok := ast.Unparen(call.Fun).(*ast.FuncLit); ok {
		lf.ps.lockBody(fl.Body, lockSet{})
	} else if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		lf.expr(sel.X, held)
	}
	lf.exprs(call.Args, held)
}

func (lf *lockFlow) exprs(list []ast.Expr, held lockSet) {
	for _, e := range list {
		lf.expr(e, held)
	}
}

// expr analyses the calls in n in evaluation order. A function literal that
// is not called on the spot is stored for later, so its body is analysed
// with no locks held.
func (lf *lockFlow) expr(n ast.Node, held lockSet) {
	if n == nil {
		return
	}
	ast.Inspect(n, func(x ast.Node) bool {
		switch x := x.(type) {
		case *ast.FuncLit:
			lf.ps.lockBody(x.Body, lockSet{})
			return false
		case *ast.CallExpr:
			lf.call(x, held)
			return false
		}
		return true
	})
}

func (lf *lockFlow) call(call *ast.CallExpr, held lockSet) {
	async := false
	switch fn := ast.Unparen(call.Fun).(type) {
	case *ast.FuncLit: // called on the spot
		lf.exprs(call.Args, held)
		lf.ps.lockBody(fn.Body, held.clone())
		return
	case *ast.SelectorExpr:
		lf.expr(fn.X, held)
		async = fn.Sel.Name == "Go" || fn.Sel.Name == "AfterFunc"
	case *ast.Ident:
		async = fn.Name == "AfterFunc"
	default:
		lf.expr(call.Fun, held)
	}
	// Function literals passed to an ordinary call are assumed to run
	// synchronously under the caller's locks (life.Safe, sort.Slice);
	// Go and AfterFunc run theirs later.
	for _, arg := range call.Args {
		if fl, ok := ast.Unparen(arg).(*ast.FuncLit); ok {
			if async {
				lf.ps.lockBody(fl.Body, lockSet{})
			} else {
				lf.ps.lockBody(fl.Body, held.clone())
			}
			continue
		}
		lf.expr(arg, held)
	}
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok && len(call.Args) == 0 {
		key := types.ExprString(sel.X)
		switch sel.Sel.Name {
		case "Lock", "RLock":
			if _, ok := held[key]; !ok {
				held[key] = call.Pos()
			}
			return
		case "Unlock", "RUnlock":
			delete(held, key)
			return
		}
	}
	if len(held) == 0 {
		return
	}
	if name := lf.ps.callbackName(call); name != "" {
		keys := make([]string, 0, len(held))
		for k := range held {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		lf.ps.c.report(call.Pos(), ruleCallbackLock, "callback %s called while holding %s (locked at %s); copy what it needs under the lock, unlock, then call", name, keys[0], lf.ps.c.where(held[keys[0]]))
	}
}

// callbackName returns the rendered callee if call invokes a
// //holepunch:callback name, otherwise "".
func (ps *pass) callbackName(call *ast.CallExpr) string {
	cb := ps.c.callbacks
	switch fn := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		if cb.funcs[ps.p.path+"."+fn.Name] || cb.member(ps.p, fn.Name) {
			return fn.Name
		}
	case *ast.SelectorExpr:
		if id, ok := fn.X.(*ast.Ident); ok {
			if imp, isImport := ps.f.imports[id.Name]; isImport {
				// A package-qualified call is a function, never a field or
				// method, so only annotated functions match (not fmt.Errorf
				// because some interface has an Errorf method).
				if cb.funcs[imp+"."+fn.Sel.Name] {
					return types.ExprString(fn)
				}
				return ""
			}
		}
		if cb.member(ps.p, fn.Sel.Name) {
			return types.ExprString(fn)
		}
	}
	return ""
}
