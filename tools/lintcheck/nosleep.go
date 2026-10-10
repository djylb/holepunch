package main

import "go/ast"

// timeSelector implements nosleep for a selector on package time.
func (ps *pass) timeSelector(sel *ast.SelectorExpr) {
	if sel.Sel.Name == "Sleep" {
		ps.c.report(sel.Pos(), ruleNoSleep, "time.Sleep cannot be cancelled; wait on a context or a Clock timer")
	}
}
