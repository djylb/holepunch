// Command lintcheck enforces the holepunch robustness rules that go vet and
// staticcheck do not know about.
//
// Usage:
//
//	go run ./tools/lintcheck [packages]
//
// Packages are directory patterns relative to the working directory
// ("./...", "./coord", "./internal/...") or import paths inside the module;
// the default is "./...". Diagnostics are printed as
// "file:line:col: rule: message". The exit status is 0 when the code is
// clean, 1 when there are diagnostics and 2 when the requested packages
// cannot be loaded.
//
// # Scope
//
// The rules guard the library. Only production code is reported: non-test
// files whose //go:build expression can hold with the holepunch_faultinject
// tag (and "ignore") off, for some setting of the other tags it mentions, so
// a file for one operating system is checked while the fault-injection
// registry is not. Packages under e2e/, tools/ and internal/tools/ are tests
// and tools, not library, and are never reported. Directories named
// testdata, directories starting with "." or "_", vendor and nested modules
// are not part of the module.
//
// The whole module is read, test files included, to gather facts that cross
// package boundaries: callback annotations and writes to package-level
// variables. A package elsewhere in the module that does not parse is
// skipped with a warning.
//
// The analysis is syntactic: go/parser, go/ast and go/build/constraint, plus
// go/types.ExprString for printing; no type checking and no
// golang.org/x/tools. Identifiers are resolved with a lexical scope walk, so
// a local variable or parameter that shadows a package-level variable or an
// import name (a parameter called net, say) is recognised as local.
//
// # Rules
//
// nobarego: a go statement may appear only in the body of the method Go of
// type Group in internal/life. Every other goroutine is started through
// (*life.Group).Go, which gives it a recover boundary and a join.
//
// noglobalstate: a package-level variable must be read-only after
// initialisation. Reported at its declaration are variables that are written
// anywhere in the module outside func init — assignment, ++/--, range
// assignment, delete, clear, copy or append on it, including writes from
// test files and from other packages (pkg.Var = x) — or whose address is
// taken, since an address lets anyone write later. Also reported are
// declarations that can only be mutable state: sync and sync/atomic types
// other than sync.Pool, channels, and pointers (&T{}, new(T), &v) except
// those to a sync.Pool and Err*/err* sentinel errors.
//
// nodirectnet: the package net identifiers that reach the operating system's
// network — Dial*, Listen*, File*, Interface*, Lookup*, Resolve*, Dialer,
// ListenConfig, Resolver and DefaultResolver — may be used only inside a
// function annotated with //holepunch:netimpl. Everything else goes through
// holepunch.Network, so tests can count and simulate every socket.
//
// nosleep: time.Sleep is forbidden, including as a function value; waits
// must be cancellable (a context or a Clock timer).
//
// callbacklock: calling user code while holding a lock is reported. User code
// is whatever carries //holepunch:callback: a function or method that calls
// user code (life.Safe), a func-typed struct field holding a user callback, or
// an interface method implemented by users. Locks are calls of Lock or RLock
// without arguments, released by Unlock or RUnlock on the same expression;
// defer x.Unlock() keeps x held to the end of the function. Lock state follows
// the statement structure of one function: branches are merged by union, paths
// ending in return or panic are dropped, loops merge with their entry state.
// Function literals passed to an ordinary call are assumed to run synchronously
// under the caller's locks (life.Safe, sort.Slice); those passed to Go or
// AfterFunc, started by go, deferred or stored run under unknown locks and are
// analysed with none held. Annotated package-level functions are matched by
// import path and name; annotated methods, fields and interface methods are
// matched by name, module-wide when exported and within their package
// otherwise. A package-qualified call (fmt.Errorf) never matches a method name.
//
// directive: //holepunch: directives must be known, take no arguments (a
// trailing // comment is allowed) and sit where they apply:
//
//	//holepunch:callback  doc comment of a function or method, doc or line
//	                      comment of a func-typed struct field or of an
//	                      interface method
//	//holepunch:netimpl   doc comment of a function in the root package or
//	                      in natprobe
//
// A misplaced or misspelt directive would otherwise silently switch a check
// off.
//
// # Limitations
//
// Without type information, callbacklock matches callbacks by name and only
// within a single function: a callback reached through an unannotated helper, a
// method value or a renamed variable is not seen, and a lock taken through one
// expression and released through another looks held. noglobalstate cannot see
// writes made by methods with pointer receivers (var r = newRegistry();
// r.Add()) or through a slice or map handed out by reference; only explicit
// address-of counts as escaping. nodirectnet covers package net, not raw
// syscalls or net/http's own dialing.
package main
