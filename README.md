# Outpost

[![CI](https://github.com/rewired89/Outpost/actions/workflows/ci.yml/badge.svg)](https://github.com/rewired89/Outpost/actions/workflows/ci.yml)
[![outpost security gate](https://github.com/rewired89/Outpost/actions/workflows/outpost.yml/badge.svg)](https://github.com/rewired89/Outpost/actions/workflows/outpost.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

Outpost is a free, open-source CI security gate that checks a domain's
**front-door hygiene** -- DNSSEC, TLS/certificate chain, Certificate
Transparency log status, and HTTP security headers -- and fails the build
(nonzero exit code) if anything has drifted from an expected baseline.

Most application security tooling looks at code. Outpost looks at the
network perimeter in front of the code: DNS resolution integrity, transport
encryption, certificate issuance, and browser-enforced security policy. It's
meant to run as one step in CI, on every deploy, so nobody has to remember to
check these by hand.

## Try it in two minutes

```sh
git clone https://github.com/rewired89/outpost.git
cd outpost
cargo build --release
./target/release/outpost scan cloudflare.com
```

No config file, no setup, no account. That last command hits a real domain
over the real internet and prints a real pass/fail report. Point it at any
domain you want a straight answer about.

## The front-door chain

A user reaching your site has to survive four independent trust decisions
before a single line of your application code runs. Outpost checks all four:

| Layer | What breaks without it | What Outpost catches |
|---|---|---|
| **DNSSEC** | A forged DNS answer is trusted by the resolver; the user lands on an attacker's server instead of yours, with no visible warning. | Resolves the domain through a locally, cryptographically validating resolver and fails if the chain of trust from the DNS root doesn't validate (`Bogus`), or if the domain simply isn't signed at all (`Insecure`). |
| **TLS / certificate chain** | Traffic in transit is readable (and rewritable) by anyone on the network path -- a coffee-shop Wi-Fi, a compromised router, a state-level intercept. | Connects over TLS, verifies the negotiated protocol version meets your configured minimum, verifies the certificate chains to a publicly trusted root (via the Mozilla root program, not whatever the CI runner's OS happens to trust -- see below), and flags certificates that are expired or expiring soon. |
| **Certificate Transparency** | Someone issues a certificate for your domain without your knowledge (a compromised CA, a social-engineered domain-validation bypass, an insider at a CA) and can impersonate your site with a real-looking padlock, undetected. | Queries public CT logs via crt.sh, diffs newly logged certificates against a local "last known good" baseline, and flags any new certificate whose issuer isn't on your allowlist. |
| **HTTP security headers** | A single XSS-shaped bug, or a bug in one embedded third party, becomes a full account-takeover or data-exfiltration primitive instead of being boxed in by the browser. | Fetches the site and verifies the presence and reasonable configuration of `Strict-Transport-Security`, `X-Content-Type-Options`, `Referrer-Policy`, and clickjacking protection (`X-Frame-Options` or a CSP `frame-ancestors` directive). |

Each check module is independent and individually configurable; disable any
of them per-domain if it doesn't apply to a particular site.

## Why the TLS check uses `webpki-roots`, not the OS trust store

Outpost's TLS check trusts the Mozilla root certificate program
(`webpki-roots`), bundled into the binary, rather than the CI runner's
operating system trust store. This is deliberate: an OS trust store can have
an enterprise MITM proxy's CA installed (common on corporate laptops and some
managed CI fleets), which would make a certificate-chain check pass even
when a middlebox is intercepting traffic -- exactly the scenario this check
exists to catch. Trusting a fixed, portable root program means the check
behaves identically everywhere it runs.

## Install

### From source

```sh
cargo install --path .
```

### From crates.io (once published)

```sh
cargo install outpost
```

### Prebuilt binaries

See the [Releases](https://github.com/rewired89/outpost/releases) page for
static Linux/macOS/Windows binaries once a release is cut. The example
GitHub Actions workflow below shows the expected download shape.

## Usage

```sh
# One-off, human-readable report for a single domain, using built-in defaults.
outpost scan example.com

# Same, but machine-readable.
outpost scan example.com --json

# Use a config file's per-domain settings for this one domain (if listed).
outpost scan example.com --config outpost.toml

# Run every domain in a config file as a CI gate. Exits 1 if any check fails.
outpost ci --config outpost.toml
```

`scan` flags: `--no-dns`, `--no-tls`, `--no-ct`, `--no-headers` disable
individual checks for that one invocation; `--tls-min-version 1.2|1.3` and
`--expiry-warning-days <n>` override those two TLS settings without needing a
config file; `--state-file <path>` controls where CT baseline state is read
from and written to (default `outpost.state.json`).

### Proposing a fix, not just reporting one

```sh
# Dry run: shows exactly what would change, touches nothing.
outpost fix example.com --repo-path .

# Opens a real pull request with that exact change.
GITHUB_TOKEN=... outpost fix example.com --repo-path . --yes --github-repo you/example-site
```

`outpost fix` only covers HTTP security headers, and only for sites using a
`_headers` file (the Netlify / Cloudflare Pages convention). That's a
deliberate, narrow scope: Outpost has no write access to your server, your
DNS, or your certificate authority, and it never will -- a checker with the
power to change what it's checking stops being a trustworthy, independent
auditor. Headers are the one finding with a config file simple and
unambiguous enough to patch safely and propose as an ordinary,
human-reviewed pull request. DNS, TLS, and CT findings still just get plain
guidance text in the report; there's no safe automated fix for those.

`fix` is dry-run by default -- it prints the full diff and changes nothing.
Add `--yes` and `--github-repo owner/repo` (with a `GITHUB_TOKEN` in the
environment) to actually write the file, push a branch, and open the pull
request. It never merges anything.

### Exit codes

- `0`: every check passed (warnings and skips are allowed).
- `1`: at least one check failed.
- `2`: the config file itself couldn't be loaded (parse error, missing file,
  or zero `[[domains]]` entries).

A `Skip` (network error, disabled check, or an external dependency like
crt.sh being unreachable) never fails the build by itself, but is printed and
included in JSON output distinctly from `Pass` -- don't treat "green" and
"skipped everything" as the same thing.

## Configuration (`outpost.toml`)

See [`outpost.example.toml`](./outpost.example.toml) for a fully annotated
example. Summary of the schema:

```toml
state_file = "outpost.state.json"   # where CT baseline state is persisted

[defaults.checks]
dns = true
tls = true
ct = true
headers = true

[defaults.tls]
min_version = "1.2"          # "1.2" or "1.3": minimum accepted negotiated version
expiry_warning_days = 14     # fail if the leaf cert expires within this window
allow_weak_ciphers = false   # see "Known limitations" below

[defaults.headers]
require = ["strict-transport-security", "x-content-type-options", "referrer-policy"]
hsts_min_max_age_seconds = 15552000
hsts_require_include_subdomains = true
hsts_require_preload = false
require_frame_protection = true
timeout_seconds = 10

[defaults.ct]
allowed_issuers = ["Let's Encrypt", "DigiCert Inc"]   # substring-matched, case-insensitive
pinned_fingerprints = []                               # SHA-256 hex, no colons
fail_on_unknown_issuer = true
timeout_seconds = 15
crtsh_url = "https://crt.sh"

[[domains]]
name = "example.com"

[[domains]]
name = "api.example.com"
[domains.tls]
min_version = "1.3"
[domains.checks]
ct = false
```

Every field under `[[domains]].checks` / `.tls` / `.headers` / `.ct`
overrides the corresponding `[defaults.*]` value for that domain only;
anything left unset falls back to the default.

### Persisting CT baseline state in CI

The Certificate Transparency check diffs newly logged certificates against a
`state_file` (default `outpost.state.json`) containing the CT log entry IDs
already seen for each domain. **Hosted CI runners are ephemeral** -- without
persisting this file between runs, every run looks like "first run" to the
CT check, which establishes a fresh baseline instead of ever detecting
drift. See [`.github/workflows/outpost.yml`](./.github/workflows/outpost.yml)
for an example using `actions/cache`; if your CI system doesn't have an
equivalent cache primitive, commit the state file back to the repo after
each run, or store it in an artifact bucket you control.

## Known limitations

This project ships four checks; none of them are half-finished, but each has
an honestly-documented scope boundary rather than a silently degraded
implementation:

- **Certificate Transparency (crt.sh)**: crt.sh is a free, unauthenticated,
  community-run aggregator with no SLA and no documented rate-limit
  contract. It will occasionally be slow, return `503`, or throttle a burst
  of requests sharing an egress IP (a fleet of CI runners, for instance).
  When it can't be reached in time, the CT check reports `Skip`, never
  `Pass` -- a skip must never be read as "no unauthorized certificate
  found." If your threat model needs a hard guarantee here, treat repeated
  `Skip`s as their own alert condition, and consider a commercial CT
  monitoring feed for anything more sensitive than best-effort. Separately:
  crt.sh's JSON search API returns issuer/subject metadata and log entry
  IDs, but not certificate fingerprints. Fingerprint pinning
  (`pinned_fingerprints`) therefore pins against the *live* leaf certificate
  served over TLS right now (reusing the TLS check's connection), not
  against every historical CT log entry.
- **Cipher suite strength**: Outpost uses `rustls`, which intentionally
  never implements or negotiates export ciphers, RC4, 3DES, or non-AEAD CBC
  suites. There is no "allow weak ciphers" bypass to defeat, because the
  library never offers them. `tls.allow_weak_ciphers` is accepted in config
  for forward compatibility and is reported as a no-op if set, rather than
  silently doing nothing.
- **CSP grading**: the headers check verifies that `Content-Security-Policy`
  is present (when required) and inspects it only for a `frame-ancestors`
  directive (used to satisfy clickjacking protection). It does not attempt
  to grade overall CSP strength (e.g. flagging `unsafe-inline` in
  `script-src`) -- that requires per-site judgment calls that would quietly
  degrade into a lint nobody trusts. Treat CSP presence as a signal, not a
  full policy audit.
- **DNSSEC without a CT-style baseline**: unlike the CT check, the DNSSEC
  check has no persisted "last known good" state -- it re-validates the live
  chain of trust on every run using the resolver's built-in root trust
  anchor. This is the correct design for DNSSEC (there's nothing analogous
  to "an unexpected new issuer" to diff against), but it does mean transient
  upstream resolver problems show up as `Skip` (`Indeterminate`) rather than
  a cached "was fine yesterday" result.

## Architecture

Single binary crate (`outpost`), library-and-binary split so integration
tests can exercise each module directly:

```
src/
  lib.rs          module wiring (pub mod ...)
  main.rs         CLI (clap): `scan`, `ci`, `fix` subcommands, orchestration, exit codes
  config.rs       outpost.toml schema, parsing, per-domain default/override resolution
  dns.rs          DNSSEC check (hickory-resolver, dnssec-ring feature)
  tls.rs          TLS/certificate chain check (rustls + webpki-roots + x509-parser)
  ct.rs           Certificate Transparency check (crt.sh) + baseline state persistence
  headers.rs      HTTP security header check (reqwest) + suggest_fixes() for `fix`
  headers_file.rs pure patcher for the Netlify/Cloudflare Pages `_headers` file format
  fix.rs          `outpost fix` orchestration: plan a change, then (only with --yes)
                  write it, commit, push, and open a pull request via GitHub's API
  report.rs       shared result types, human-readable + JSON rendering, exit code logic
```

Each check module exposes a pure, network-free `evaluate()` (or
`evaluate`-shaped) function separate from the network I/O, so the decision
logic is unit-testable without a live connection.

## Testing

```sh
cargo test                    # unit tests + mocked-failure integration tests (no real internet needed)
cargo test -- --ignored       # + live checks against real public domains (see below)
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

Test tiers:

1. **Unit tests** (in each module, `#[cfg(test)] mod tests`): pure logic --
   config merge/override precedence, header parsing and HSTS math, DNSSEC
   proof-status classification, CT baseline diffing, TLS expiry math against
   certificates generated on the fly with `rcgen`. No network.
2. **Mocked-failure integration tests** (`tests/integration.rs`, run by
   default): exercise the real network + parsing code paths against local
   fixtures -- a `wiremock` HTTP server standing in for a target's headers or
   crt.sh's API, and a hand-rolled local `rustls` TLS server presenting a
   certificate that can't possibly be trusted (self-signed, generated per
   test run) standing in for a rogue/intercepted certificate.
3. **Live integration tests** (`tests/integration.rs`, `#[ignore]`d by
   default -- run with `cargo test -- --ignored`): hit real, stable public
   domains. Gated behind `--ignored` so a target rotating its certificate or
   changing a header policy never breaks this crate's own CI by surprise.
   Domains chosen, and what's assumed to always hold:
   - `cloudflare.com` -- used by `hickory-resolver`'s own upstream test suite
     (`resolver::tests::sec_lookup_test`) as the canonical "known to validate
     as DNSSEC `Secure`" domain; also a major CDN/TLS vendor that dogfoods
     HSTS and modern TLS on its own marketing domain. Assumed: DNSSEC-signed,
     valid public certificate chain, TLS 1.3, HSTS present.
   - `hickory-dns.org` -- used by `hickory-resolver`'s own test suite
     (`resolver::tests::sec_lookup_fails_test`) as a domain that exists but
     is deliberately *not* DNSSEC-signed. Assumed: resolves, but DNSSEC
     `Insecure`.
   - `github.com` -- long-standing, well-documented security header policy.
     Assumed: serves the required baseline header set over HTTPS.

## GitHub Actions

[`.github/workflows/outpost.yml`](./.github/workflows/outpost.yml) is a
working example in this repo (it builds Outpost from source and gates on
`cloudflare.com` as a demo target) that also documents, in comments, exactly
what to change to gate your own domains in your own repository: swap the
"build from source" step for `cargo install outpost` or a release binary
download, point the config at your domains, and keep the `actions/cache`
step so the CT baseline survives between runs.

## Contributing

Outpost is open source (MIT licensed) and built by a solo developer -- issues,
questions, and pull requests are genuinely welcome. See
[`CONTRIBUTING.md`](./CONTRIBUTING.md) for how to build, test, and submit a
change, and [`CLAUDE.md`](./CLAUDE.md) for the deeper design reasoning behind
each module if you're planning something non-trivial.
