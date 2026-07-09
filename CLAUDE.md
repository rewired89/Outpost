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
- `src/main.rs` -- clap CLI (`scan`, `ci`), orchestration
  (`run_domain`: TLS runs first per domain so its leaf cert DER is available
  to the CT check without a second connection), exit codes (0 pass / 1
  check failure / 2 config load error).

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
