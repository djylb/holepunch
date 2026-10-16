package main

import (
	"go/ast"
	"go/token"
	"go/types"
	"sort"
	"strings"
)

// lockSet maps a held lock, keyed by the rendered receiver expression, to
// the position of the Lock call that took it. A key with the heldAtReturn
// prefix marks a lock still held when the function returns, because its
// Unlock is deferred or because the caller of a function literal holds it
// across the call: the calls deferred from then on run with it held.
type lockSet map[string]token.Pos

const heldAtReturn = "defer "

// locks returns the held locks, sorted, without the heldAtReturn marks.
func (s lockSet) locks() []string {
	var out []string
	for k := range s {
		if !strings.HasPrefix(k, heldAtReturn) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// atReturn returns the locks held while a call deferred now runs: those
// marked as held at return.
func (s lockSet) atReturn() lockSet {
	out := lockSet{}
	for k, pos := range s {
		if lock, ok := strings.CutPrefix(k, heldAtReturn); ok {
			out[lock] = pos
		}
	}
	return out
}

// entered returns the state a function literal starts with when it runs
// synchronously under s: the held locks, each marked as held at the
// literal's return. The marks of the enclosing function concern that
// function's return and are dropped.
func (s lockSet) entered() lockSet {
	out := lockSet{}
	for k, pos := range s {
		if !strings.HasPrefix(k, heldAtReturn) {
			out[k] = pos
			out[heldAtReturn+k] = pos
		}
	}
	return out
}

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
		lf.goCall(s.Call, held)
	case *ast.DeferStmt:
		lf.deferCall(s.Call, held)
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
	states := append([]lockSet{entry}, t.exits...)
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

// goCall handles a go statement: the function value and arguments are
// evaluated now, the call runs on another goroutine, under none of the
// caller's locks.
func (lf *lockFlow) goCall(call *ast.CallExpr, held lockSet) {
	if fl, ok := ast.Unparen(call.Fun).(*ast.FuncLit); ok {
		lf.ps.lockBody(fl.Body, lockSet{})
	} else if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		lf.expr(sel.X, held)
	}
	lf.exprs(call.Args, held)
}

// deferCall handles a defer statement. The function value and arguments are
// evaluated now; the call, and the function literals passed to it, run when
// the function returns, before the Unlocks deferred earlier, so under those
// locks. A deferred Unlock keeps its lock held to the end of the function
// and marks it for the calls deferred after it; so does a deferred function
// literal that unlocks a held lock. A deferred Lock (x.Unlock(); defer
// x.Lock()) clears the mark: the calls deferred after it run before it, when
// the lock must be free.
func (lf *lockFlow) deferCall(call *ast.CallExpr, held lockSet) {
	fl, isLit := ast.Unparen(call.Fun).(*ast.FuncLit)
	switch fn := ast.Unparen(call.Fun).(type) {
	case *ast.SelectorExpr:
		lf.expr(fn.X, held)
		if key, unlock := unlockOf(call); unlock {
			if pos, ok := held[key]; ok {
				held[heldAtReturn+key] = pos
			}
			return
		}
		if len(call.Args) == 0 && (fn.Sel.Name == "Lock" || fn.Sel.Name == "RLock") {
			delete(held, heldAtReturn+types.ExprString(fn.X))
			return
		}
	case *ast.FuncLit, *ast.Ident:
	default:
		lf.expr(fn, held)
	}
	run := held.atReturn()
	if !isLit {
		lf.args(call, held, run)
		lf.reportHeld(call, run)
		return
	}
	// The literal starts under run, which stays held at its return, and under
	// the held locks it releases itself.
	body := run.entered()
	for _, key := range unlocksIn(fl.Body) {
		if pos, ok := held[key]; ok {
			body[key] = pos
			held[heldAtReturn+key] = pos
		}
	}
	lf.exprs(call.Args, held)
	lf.ps.lockBody(fl.Body, body)
}

// unlockOf returns the lock an Unlock or RUnlock call releases.
func unlockOf(call *ast.CallExpr) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || len(call.Args) != 0 || sel.Sel.Name != "Unlock" && sel.Sel.Name != "RUnlock" {
		return "", false
	}
	return types.ExprString(sel.X), true
}

// unlocksIn returns the locks a function body releases, not counting nested
// function literals.
func unlocksIn(body *ast.BlockStmt) []string {
	var out []string
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.CallExpr:
			if key, ok := unlockOf(n); ok {
				out = append(out, key)
			}
		}
		return true
	})
	return out
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
	switch fn := ast.Unparen(call.Fun).(type) {
	case *ast.FuncLit: // called on the spot
		lf.exprs(call.Args, held)
		lf.ps.lockBody(fn.Body, held.entered())
		return
	case *ast.SelectorExpr:
		lf.expr(fn.X, held)
	default:
		lf.expr(call.Fun, held)
	}
	lf.args(call, held, held)
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
	lf.reportHeld(call, held)
}

// args analyses the arguments of call, evaluated under held. Function
// literals passed to an ordinary call are assumed to run synchronously, when
// the call runs, under run (life.Safe, sort.Slice); Go and AfterFunc run
// theirs later, under unknown locks.
func (lf *lockFlow) args(call *ast.CallExpr, held, run lockSet) {
	async := false
	switch fn := ast.Unparen(call.Fun).(type) {
	case *ast.SelectorExpr:
		async = fn.Sel.Name == "Go" || fn.Sel.Name == "AfterFunc"
	case *ast.Ident:
		async = fn.Name == "AfterFunc"
	}
	for _, arg := range call.Args {
		if fl, ok := ast.Unparen(arg).(*ast.FuncLit); ok {
			if async {
				lf.ps.lockBody(fl.Body, lockSet{})
			} else {
				lf.ps.lockBody(fl.Body, run.entered())
			}
			continue
		}
		lf.expr(arg, held)
	}
}

// reportHeld reports call when it invokes a callback while a lock is held.
func (lf *lockFlow) reportHeld(call *ast.CallExpr, held lockSet) {
	keys := held.locks()
	if len(keys) == 0 {
		return
	}
	if name := lf.ps.callbackName(call); name != "" {
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
