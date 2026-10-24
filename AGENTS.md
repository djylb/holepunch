# AGENTS.md

- Run `make ci` before you finish; it must pass. It formats, vets, lints
  (`tools/lintcheck`) and runs the race tests of every module.
- The root module has no external dependencies, not even for tests. Use the
  standard library. Only the `quicpath` and `standalone` modules may depend
  on quic-go, and the root module never imports them.
- `standalone` uses the library's public API only.
- Treat everything from gateways, observers, peers and the kernel as
  untrusted: bound every read and every parse.
- Punch packets are encrypted per session and carry no constant bytes.
- User callbacks run inside a recover boundary and never under a lock.
- Tests must not leak goroutines; every package checks it on exit.
- Commit subjects are short, English and imperative.
- Never commit host names, IP addresses or credentials.
