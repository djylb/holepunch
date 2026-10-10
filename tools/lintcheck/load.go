package main

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// faultTag is the build tag of test-only fault injection.
// Files that cannot be built without it are not production code.
const faultTag = "holepunch_faultinject"

// nonLibrary lists the module directories that hold tests and tools rather
// than library code. Their packages are loaded, so that
// their writes to library variables are seen, but never reported.
func nonLibrary() []string { return []string{"e2e", "tools", "internal/tools"} }

// module is the set of packages of one Go module.
type module struct {
	root string // absolute directory containing go.mod
	path string // module path
	fset *token.FileSet
	pkgs []*pkg // sorted by rel
}

// pkg is one directory of Go files.
type pkg struct {
	dir     string // absolute
	rel     string // slash-separated, relative to the module root; "" for the root
	path    string // import path
	library bool   // the rules apply
	files   []*file
	tests   []*file         // _test.go files, read only to find writes to package variables
	vars    map[string]bool // package-level variables of the production files
	decls   map[string]bool // every package-level name of the production files
	err     error           // first parse error; the package is otherwise empty
}

type file struct {
	ast     *ast.File
	imports map[string]string // local name → import path; blank and dot imports excluded
}

// findModuleRoot returns the nearest directory at or above dir with a go.mod.
func findModuleRoot(dir string) (string, error) {
	for d := dir; ; {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d, nil
		}
		parent := filepath.Dir(d)
		if parent == d {
			return "", fmt.Errorf("no go.mod at or above %s", dir)
		}
		d = parent
	}
}

func readModulePath(gomod string) (string, error) {
	f, err := os.Open(gomod)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }() // read-only: nothing is lost if closing fails
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if rest, ok := strings.CutPrefix(line, "module"); ok && rest != "" && (rest[0] == ' ' || rest[0] == '\t') {
			p := strings.TrimSpace(rest)
			if unq, err := strconv.Unquote(p); err == nil {
				p = unq
			}
			return p, nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("%s: no module directive", gomod)
}

// loadModule parses every package under root. A package that does not parse
// is kept with its error, so that a broken package elsewhere in the module
// does not stop checking the requested ones.
func loadModule(root string) (*module, error) {
	modPath, err := readModulePath(filepath.Join(root, "go.mod"))
	if err != nil {
		return nil, err
	}
	m := &module{root: root, path: modPath, fset: token.NewFileSet()}
	err = filepath.WalkDir(root, func(dir string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		if dir != root {
			name := d.Name()
			if name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				return filepath.SkipDir // nested module
			}
		}
		p, err := m.loadPackage(dir)
		if err != nil {
			return err
		}
		if p != nil {
			m.pkgs = append(m.pkgs, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(m.pkgs, func(i, j int) bool { return m.pkgs[i].rel < m.pkgs[j].rel })
	return m, nil
}

func (m *module) loadPackage(dir string) (*pkg, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(m.root, dir)
	if err != nil {
		return nil, err
	}
	p := &pkg{dir: dir, rel: filepath.ToSlash(rel), path: m.path, library: true, vars: map[string]bool{}, decls: map[string]bool{}}
	if p.rel == "." {
		p.rel = ""
	} else {
		p.path += "/" + p.rel
	}
	for _, prefix := range nonLibrary() {
		if p.rel == prefix || strings.HasPrefix(p.rel, prefix+"/") {
			p.library = false
		}
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
			continue
		}
		af, err := parser.ParseFile(m.fset, filepath.Join(dir, name), nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			return &pkg{dir: dir, rel: p.rel, path: p.path, library: p.library, err: err}, nil
		}
		f := newFile(af)
		switch {
		case strings.HasSuffix(name, "_test.go"):
			p.tests = append(p.tests, f)
		case production(af):
			p.files = append(p.files, f)
		}
	}
	if len(p.files) == 0 && len(p.tests) == 0 {
		return nil, nil
	}
	p.collectDecls()
	return p, nil
}

// production reports whether the file is part of some production build: its
// //go:build expression can be satisfied with the fault-injection tag and
// "ignore" off and some setting of every other tag it mentions. A file for
// one operating system or architecture is therefore production code.
func production(f *ast.File) bool {
	expr := buildConstraint(f)
	if expr == nil {
		return true
	}
	var free []string
	seen := map[string]bool{}
	collectTags(expr, func(tag string) {
		if tag != faultTag && tag != "ignore" && !seen[tag] {
			seen[tag] = true
			free = append(free, tag)
		}
	})
	if len(free) > 16 {
		return true // too many to enumerate; check the file rather than skip it
	}
	for mask := 0; mask < 1<<len(free); mask++ {
		ok := expr.Eval(func(tag string) bool {
			for i, t := range free {
				if t == tag {
					return mask&(1<<i) != 0
				}
			}
			return false // faultTag and ignore
		})
		if ok {
			return true
		}
	}
	return false
}

func buildConstraint(f *ast.File) constraint.Expr {
	for _, g := range f.Comments {
		if g.Pos() > f.Package {
			break
		}
		for _, c := range g.List {
			if constraint.IsGoBuild(c.Text) {
				if expr, err := constraint.Parse(c.Text); err == nil {
					return expr
				}
			}
		}
	}
	return nil
}

func collectTags(e constraint.Expr, add func(string)) {
	switch e := e.(type) {
	case *constraint.TagExpr:
		add(e.Tag)
	case *constraint.NotExpr:
		collectTags(e.X, add)
	case *constraint.AndExpr:
		collectTags(e.X, add)
		collectTags(e.Y, add)
	case *constraint.OrExpr:
		collectTags(e.X, add)
		collectTags(e.Y, add)
	}
}

func newFile(af *ast.File) *file {
	f := &file{ast: af, imports: map[string]string{}}
	for _, spec := range af.Imports {
		p, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		name := importName(p)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name != "_" && name != "." {
			f.imports[name] = p
		}
	}
	return f
}

// importName guesses the package name of an import path without loading it:
// the last element, skipping a major-version suffix such as "/v2".
func importName(p string) string {
	base := path.Base(p)
	if len(base) > 1 && base[0] == 'v' && strings.Trim(base[1:], "0123456789") == "" {
		base = path.Base(path.Dir(p))
	}
	return base
}

func (p *pkg) collectDecls() {
	for _, f := range p.files {
		for _, d := range f.ast.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil {
					p.decls[d.Name.Name] = true
				}
			case *ast.GenDecl:
				for _, s := range d.Specs {
					switch s := s.(type) {
					case *ast.ValueSpec:
						for _, n := range s.Names {
							p.decls[n.Name] = true
							if d.Tok == token.VAR && n.Name != "_" {
								p.vars[n.Name] = true
							}
						}
					case *ast.TypeSpec:
						p.decls[s.Name.Name] = true
					}
				}
			}
		}
	}
}

// match returns the library packages selected by patterns, interpreted
// relative to wd, and warnings for "..." patterns that match nothing.
func (m *module) match(wd string, patterns []string) ([]*pkg, []string, error) {
	selected := map[*pkg]bool{}
	var warnings []string
	for _, pat := range patterns {
		dir, recursive, err := m.patternDir(wd, pat)
		if err != nil {
			return nil, nil, err
		}
		n := 0
		for _, p := range m.pkgs {
			if !p.library || (p.err == nil && len(p.files) == 0) {
				continue
			}
			if p.dir == dir || recursive && within(dir, p.dir) {
				selected[p] = true
				n++
			}
		}
		if n == 0 {
			if !recursive {
				return nil, nil, fmt.Errorf("%s: no library package with production Go files in %s", pat, dir)
			}
			warnings = append(warnings, fmt.Sprintf("%q matched no packages", pat))
		}
	}
	var out []*pkg
	for _, p := range m.pkgs {
		if selected[p] {
			out = append(out, p)
		}
	}
	return out, warnings, nil
}

func (m *module) patternDir(wd, pat string) (dir string, recursive bool, err error) {
	if pat == "..." {
		pat = "./..."
	}
	if rest, ok := strings.CutSuffix(pat, "/..."); ok {
		pat, recursive = rest, true
	}
	switch {
	case pat == m.path:
		dir = m.root
	case strings.HasPrefix(pat, m.path+"/"):
		dir = filepath.Join(m.root, filepath.FromSlash(strings.TrimPrefix(pat, m.path+"/")))
	case filepath.IsAbs(pat):
		dir = filepath.Clean(pat)
	default:
		dir = filepath.Join(wd, filepath.FromSlash(pat))
	}
	if !within(m.root, dir) {
		return "", false, fmt.Errorf("%s: outside module %s", pat, m.path)
	}
	return dir, recursive, nil
}

// within reports whether dir is parent or below it.
func within(parent, dir string) bool {
	rel, err := filepath.Rel(parent, dir)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
