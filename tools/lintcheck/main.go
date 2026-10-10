package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func main() {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "lintcheck:", err)
		os.Exit(2)
	}
	os.Exit(run(wd, os.Args[1:], os.Stdout, os.Stderr))
}

// run is the whole command with its environment passed in, so tests can call
// it. It returns the exit status.
func run(wd string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("lintcheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: lintcheck [packages]   (default ./...)")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	patterns := fs.Args()
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}
	root, err := findModuleRoot(wd)
	if err != nil {
		fmt.Fprintln(stderr, "lintcheck:", err)
		return 2
	}
	mod, err := loadModule(root)
	if err != nil {
		fmt.Fprintln(stderr, "lintcheck:", err)
		return 2
	}
	targets, warnings, err := mod.match(wd, patterns)
	if err != nil {
		fmt.Fprintln(stderr, "lintcheck:", err)
		return 2
	}
	for _, p := range mod.pkgs {
		if p.err != nil && !contains(targets, p) {
			warnings = append(warnings, fmt.Sprintf("skipping %s, which does not parse: %v", p.dir, p.err))
		}
	}
	for _, w := range warnings {
		fmt.Fprintln(stderr, "lintcheck: warning:", w)
	}
	for _, p := range targets {
		if p.err != nil {
			fmt.Fprintln(stderr, "lintcheck:", p.err)
			return 2
		}
	}
	diags := check(mod, targets)
	for _, d := range diags {
		name := d.pos.Filename
		if rel, err := filepath.Rel(wd, name); err == nil && within(wd, name) {
			name = rel
		}
		fmt.Fprintf(stdout, "%s:%d:%d: %s: %s\n", name, d.pos.Line, d.pos.Column, d.rule, d.msg)
	}
	if len(diags) > 0 {
		return 1
	}
	return 0
}

func contains(list []*pkg, p *pkg) bool {
	for _, q := range list {
		if q == p {
			return true
		}
	}
	return false
}
