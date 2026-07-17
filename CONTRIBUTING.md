# Contributing to Outpost

Thanks for taking a look. Outpost is a solo project, so response times won't
be instant, but issues, questions, and pull requests are genuinely welcome.

## Getting set up

```sh
git clone https://github.com/rewired89/Outpost.git
cd Outpost
cargo build
cargo test
```

No config file or account is needed to build or run the test suite -- see
the "Testing" section of [`README.md`](./README.md) for what each test tier
covers and why.

## Before opening a pull request

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
```

All three run in CI (`.github/workflows/ci.yml`) on every pull request, so
running them locally first just saves a round trip.

## Where to look before making a change

- [`README.md`](./README.md) explains what each check does and why, plus the
  config schema.
- [`CLAUDE.md`](./CLAUDE.md) is the deeper reference: the module map, the
  design decisions worth preserving (why DNSSEC-insecure is a failure and
  not a neutral state, why `Skip` must never be conflated with `Pass`, why
  Outpost never gains write access to what it's checking, etc.), and the
  testing conventions each module follows. If you're planning something
  beyond a small fix, read the relevant section there first -- several
  things that look like reasonable changes are deliberate design decisions
  with a reason written down.

## Reporting a security issue

Outpost checks other systems' security posture; please don't file a public
issue for a vulnerability in Outpost itself. Open a private security
advisory instead (repository's "Security" tab -> "Report a vulnerability").

## Scope

New checks, new config fields, and new output formats are all reasonable
things to propose. One boundary that isn't up for debate without a very
strong reason: Outpost never gains write access to the domain, DNS, or
certificate authority it's checking, and never writes, commits, or pushes
anything on the user's behalf either -- `outpost fix` computes and prints
the exact header fix and stops there. See the "Outpost never gains write
access" note in `CLAUDE.md` for why, including why an earlier
pull-request-opening mode was removed rather than kept.
