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
// anywhere in the module outside func init and the package-level
// initialisers — assignment, ++/--, range assignment, delete, clear, copy or
// append on it, including writes from test files and from other packages
// (pkg.Var = x) — or whose address is taken, since an address lets anyone
// write later. A function literal that init or an initialiser creates
// without calling it runs later, so its writes count. Also reported are
// declarations that can only be mutable state: sync and sync/atomic types
// other than sync.Pool, channels, and pointers (&T{}, new(T), &v) except
// those to a sync.Pool and Err*/err* sentinel errors.
//
// nodirectnet: the package net identifiers that reach the operating system's
// network — Dial*, Listen*, File*, Interface*, Lookup*, Resolve*, Dialer,
// ListenConfig, Resolver and DefaultResolver — may be used only inside a
// function annotated with //holepunch:netimpl. Everything else goes through
// holepunch.Network, so tests can count and simulate every socket. A dot
// import of net is reported too: it would hide those identifiers.
//
// nosleep: time.Sleep is forbidden, including as a function value; waits
// must be cancellable (a context or a Clock timer). A dot import of time is
// reported too: it would hide the call.
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
// AfterFunc, started by go or stored run under unknown locks and are analysed
// with none held. A deferred call runs at return, before the Unlocks deferred
// earlier on its path, so under those locks, and so do the function literals
// passed to it unless it is Go or AfterFunc; a function literal that runs
// synchronously returns under the locks it was called under, so the calls it
// defers run under them too. A deferred function literal that unlocks a held
// lock counts as that lock's deferred Unlock, and a deferred Lock (x.Unlock();
// defer x.Lock()) releases x for the calls deferred after it, which run
// before it. Annotated package-level functions are matched by import path and
// name; annotated methods, fields and interface methods are matched by name,
// module-wide when exported and within their package otherwise. A
// package-qualified call (fmt.Errorf) never matches a method name.
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
// off; so would a known one written with a space after the slashes
// ("// holepunch:callback"), which is reported too unless more prose
// follows it.
//
// # Limitations
//
// Without type information, callbacklock matches callbacks by name and only
// within a single function: a callback reached through an unannotated helper, a
// method value or a renamed variable is not seen, and a lock taken through one
// expression and released through another looks held. Its lock state is a
// single pass over the statements, not a fixed point, and errs both ways:
//
//   - a loop body is analysed once, from the state on entry: a lock still
//     held at the end of one iteration, or at a continue, is not seen at the
//     top of the next, and every loop, for {} included, is taken to possibly
//     run zero times;
//   - goto ends a path, and fallthrough carries a clause's state to the end
//     of the switch, not into the next clause;
//   - a function literal's own Lock and Unlock calls do not change its
//     caller's state: a literal that releases a lock its caller holds without
//     retaking it still has the calls it defers reported, and a literal that
//     takes a lock leaves the caller's later calls unreported;
//   - a deferred function literal that takes a lock is not a deferred Lock,
//     one that unlocks counts as a deferred Unlock even when the unlock is
//     conditional, and a deferred Unlock counts only for a lock held when it
//     is deferred;
//   - TryLock is not a Lock;
//   - Go and AfterFunc are recognised by name alone, and a function literal
//     that an ordinary call stores instead of running (sync.OnceFunc) is
//     still analysed under the caller's locks;
//   - function literals in package-level variable initialisers are not
//     analysed.
//
// noglobalstate cannot see writes made by methods with pointer receivers
// (var r = newRegistry(); r.Add()) or through a slice or map handed out by
// reference; only explicit address-of counts as escaping. nodirectnet covers
// package net, not raw syscalls or net/http's own dialing.
package main
