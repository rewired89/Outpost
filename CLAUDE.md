# CLAUDE.md

Guidance for Claude Code sessions working in this repository.

## What this is

Outpost is a Rust CLI: a CI security gate that checks a domain's DNSSEC, TLS
certificate chain, Certificate Transparency log status, and HTTP security
headers, failing the build on drift from a configured baseline. See
`README.md` for the full user-facing explanation and `outpost.example.toml`
for the config schema.

## Build / test / lint

```sh
cargo build --release
cargo test                    # unit + mocked-failure integration tests, no real internet needed
cargo test -- --ignored       # + live tests against real public domains
cargo clippy --all-targets -- -D warnings
cargo fmt --all
```

The crate is `[lib]` + `[[bin]]` split (`src/lib.rs` declares the modules,
`src/main.rs` is a thin clap CLI over the library) specifically so
`tests/integration.rs` can call each module's public functions directly.
Keep that split when adding new checks or refactoring `main.rs`.

## Module map

- `src/config.rs` -- `outpost.toml` schema. `Defaults` holds concrete
  values; `DomainEntry` holds `Option<T>` overrides; `DomainEntry::resolve()`
  merges the two into an `EffectiveDomain`. When adding a new configurable
  field, it needs to exist in three places: the `*Config` struct (concrete),
  the corresponding `*Override` struct (`Option<T>`), and the merge in
  `resolve()`. Config structs use `#[serde(deny_unknown_fields)]` --
  intentional, so a typo'd TOML key fails loudly instead of being silently
  ignored.
- `src/dns.rs` -- DNSSEC via `hickory-resolver` (feature `dnssec-ring`).
  Always validates locally against the crate's built-in IANA root trust
  anchor (`ResolverOpts::validate = true`); Cloudflare (`1.1.1.1`) is used
  only as transport, never as a trust source. Classification: any `Bogus`
  record -> Fail; all `Secure` -> Pass; any `Insecure` (and none `Bogus`) ->
  Fail (unsigned zone is treated as a finding, not a neutral state);
  otherwise -> Skip (`Indeterminate`, e.g. transient resolver failure). The
  network I/O (`check`) is separate from the pure classifier (`evaluate`,
  private) so the latter is unit-tested with hand-built `Proof` values.
- `src/tls.rs` -- `rustls` + `webpki-roots` (not the OS trust store --
  deliberate, see README). `connect()` wraps `connect_to(sni, host, port)`;
  the three-argument form exists so tests can point the TCP connection at a
  local mock server while exercising real chain validation. `evaluate()` and
  `error_to_result()` are both `pub` (not just `pub(crate)`) so
  `tests/integration.rs` and `main.rs` can share them without a third
  network round trip.
- `src/ct.rs` -- queries crt.sh's JSON search API, diffs against
  `BaselineState` (JSON file, path from `config.state_file`), flags new
  entries whose issuer isn't in `allowed_issuers`. First run for a domain
  (empty baseline) always establishes baseline without failing -- don't
  "fix" this to compare against nothing; that's the intended behavior for a
  diff-based check. Also supports `pinned_fingerprints` against the *live*
  leaf cert (crt.sh's API doesn't return fingerprints, only issuer/subject
  metadata + log IDs), which is why `ct::check` takes an
  `Option<&[u8]>` leaf DER parameter that `main.rs` sources from the TLS
  check's connection.
- `src/headers.rs` -- `reqwest`. `check(domain, cfg)` builds
  `https://{domain}/` and delegates to `check_url(url, cfg)`, which exists
  so tests can point it at a local mock HTTP server. `evaluate()` is the
  pure, network-free header-set classifier.
- `src/report.rs` -- `Status` (Pass/Warn/Fail/Skip), `CheckResult`,
  `DomainReport`, `Report`. Only `Fail` fails the build
  (`Report::has_failure`); `Skip` must never be conflated with `Pass` in any
  new rendering code.
- `src/main.rs` -- clap CLI (`scan`, `ci`, `fix`), orchestration
  (`run_domain`: TLS runs first per domain so its leaf cert DER is available
  to the CT check without a second connection), exit codes (0 pass / 1
  check failure / 2 config load error).
- `src/headers_file.rs` -- pure patcher for the Netlify/Cloudflare Pages
  `_headers` file format. `apply_fixes(existing, fixes)` parses into
  path-pattern blocks, patches only the `/*` (site-wide) block, and leaves
  every other block byte-for-byte untouched. No I/O; `fix.rs` does the one
  read.
- `src/fix.rs` -- `outpost fix`. `plan()` reads the existing `_headers` file
  (if any) and computes the patched contents; that's the entire module.
  Deliberately, permanently read-only: no git, no GitHub API, no write to
  disk. An earlier version wrote the file, committed it, and opened a pull
  request via GitHub's API behind a `--yes` flag -- it worked, but the
  GitHub API leg turned out to be a bad edge for a small, easily-doubted
  tool to ship with: a token/permissions issue on one real test account
  produced a bare, confusing 404 with no reliable local way to diagnose it
  over a remote session, and a security tool with an unreliable "trust me,
  click yes" step erodes trust in the rest of it faster than not having the
  feature at all. Removed rather than left half-working. If this comes
  back, it should be new, not a revert -- rethink the trust story (e.g. a
  local git-format-patch/diff file the user applies themselves, no network
  call at all) rather than reintroducing a bearer-token REST call as the
  last mile.

## Design decisions worth preserving

- **Skip is not Pass.** Every check module returns `Skip` (not `Pass`, not
  silently omitted) when it can't reach its dependency (crt.sh, the target
  host, the resolver). `Report::has_failure()` only looks at `Fail`. Don't
  change `Skip` to fail the build or to be swallowed -- both directions
  defeat the point of surfacing it distinctly.
- **Unsigned DNS and unauthenticated CT are findings, not neutral states.**
  `Proof::Insecure` (no DNSSEC at all) fails the DNS check; an empty
  `allowed_issuers` list makes the CT check `Warn` (not silently `Pass`) on
  new certs, because the tool can't tell authorized from unauthorized
  issuance without that list.
- **rustls over native-tls/openssl was a deliberate choice**, not just "the
  Rust-y option" -- it means there is no legacy cipher suite to accidentally
  allow. Don't add an openssl/native-tls fallback path "for compatibility"
  without revisiting the "Known limitations" section of the README, since
  that section's claims depend on rustls being the only TLS implementation
  in the tree.
- **CT log entry fingerprints don't come from crt.sh.** If you're tempted to
  add fingerprint comparison against historical CT entries (not just the
  live cert), that requires fetching each entry's full certificate
  separately (extra crt.sh round trips per entry, worse rate-limit
  exposure) -- think about that tradeoff before doing it, don't just wire it
  up.
- **Surface the real cause of a network error, not reqwest's top-level
  message.** `ct::describe_error` walks the `source()` chain instead of just
  printing `{e}`, because reqwest's `Display` for a failed request is often
  just "error sending request for url (...)" with the actually useful
  detail (DNS failure, TLS error, HTTP status) buried in `.source()`. This
  came from a real live run where a vague `Skip` message was undiagnosable
  until this fix landed. Apply the same pattern anywhere else a network
  error gets turned into a report string.
- **Outpost never gains write access to the thing it's checking, full stop.**
  `fix.rs` exists specifically because this boundary matters: it computes
  and prints the exact fix for headers -- the one finding with a config
  file (`_headers`) simple enough to patch safely -- and stops there. It
  never writes the file, never touches git, never calls a network API to
  act on your behalf. Don't extend `fix` to DNS, TLS, or CT, and don't add
  a mode that writes anything, opens anything, or calls out to git/GitHub
  on the user's behalf -- a checker with the power to change what it's
  checking stops being a trustworthy, independent auditor, and becomes the
  single highest-value target in the whole system (the same failure mode
  the CT check exists to catch in the first place). This was tried once
  (`fix.rs`'s prior `--yes` mode); see that entry in the module map above
  for why it was removed instead of debugged further.
- **The demo `outpost.toml` at the repo root scans `cloudflare.com` only --
  don't add `github.com` back to it.** It was there originally and got
  removed after a live run confirmed github.com genuinely has no DNSSEC
  deployed, which would fail this repo's own demo CI workflow on every
  single run, forever. That's a correct finding about github.com, not a bug
  -- but a permanently red Actions badge on the tool's own demo is a bad
  first impression for anyone evaluating whether to try it. If you add more
  demo domains, verify with a live run first that they pass all four checks
  cleanly.

## Testing conventions

- Pure classification logic (`evaluate`-shaped functions) gets unit tests
  in the same module, using hand-built inputs (`HeaderMap`, `Vec<Proof>`,
  `rcgen`-generated certs, literal `CrtShEntry` values) -- no network.
- `tests/integration.rs` mocked-failure tests (run by default, no real
  internet) use `wiremock` for HTTP-shaped dependencies (headers, crt.sh)
  and a hand-rolled local `rustls` server (self-signed cert via `rcgen`) for
  the TLS chain-rejection path. Keep new integration tests in this tier
  unless they truly need the real internet.
- Live-domain tests are `#[ignore]`d by default and documented with *why*
  that specific domain was chosen and what's assumed to always hold about
  it (see the "Testing" section of README.md). If you add one, follow that
  pattern -- a live test with no justification comment is a future flaky
  failure with no context.

## A note on sandboxed/restricted dev environments

If you're iterating on this project inside a network-sandboxed environment
(as this one was, during initial development), be aware of two things that
look like bugs in Outpost but are the sandbox instead:

1. **TLS interception**: some sandboxes MITM outbound HTTPS with their own
   CA for policy/monitoring reasons. Since `tls.rs` deliberately trusts only
   `webpki-roots` (not the OS/sandbox trust store), any live TLS check run
   inside such a sandbox will correctly report `Fail` (`UnknownIssuer`) even
   against a perfectly healthy real domain. That's the check working as
   designed, not a defect.
2. **Blocked/degraded raw DNS over TCP port 53**: some sandboxes allow
   direct outbound UDP/53 but block TCP/53 (needed for DNSSEC responses too
   large for a single UDP datagram). This can make `dns::check` report
   `Bogus` (not `Skip`) for a domain that is, in reality, correctly signed,
   because the resolver library falls back to a blocked TCP path and
   observes a truncated/incomplete validation chain.

Before concluding either check has a real bug based on a live run inside
such an environment, verify with a raw socket test (`nc`/Python
`socket.create_connection`) whether outbound TCP/53 and unproxied TLS to
port 443 actually work in that environment. The unit and mocked-integration
test suites (which avoid the real internet entirely) are the reliable
signal in these environments; treat live-test results there as inconclusive,
not authoritative.
