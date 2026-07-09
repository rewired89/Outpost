//! Integration tests.
//!
//! Two categories, split by whether they touch the real internet:
//!
//! 1. **Mocked failure cases** (run by default, no network egress needed
//!    beyond localhost): a local `wiremock` HTTP server stands in for a
//!    target site's headers/crt.sh responses, and a hand-rolled local
//!    `rustls` TLS server stands in for a domain presenting a certificate
//!    chain that shouldn't be trusted. These exercise the real network +
//!    parsing code path, not just the pure `evaluate()` functions (which
//!    already have their own focused unit tests in each module).
//!
//! 2. **Live checks against real, stable public domains** (`#[ignore]`d by
//!    default -- run explicitly with `cargo test -- --ignored`). Hitting the
//!    real internet from a test suite is inherently flaky: a target's cert
//!    rotates, a header policy changes, a network egress path is firewalled.
//!    Gating these behind `--ignored` matches the ask ("integration tests
//!    ... plus mocked failure cases so tests don't depend on someone else's
//!    cert rotating out from under CI") -- they're for a human (or a
//!    scheduled, non-blocking job) to run deliberately, not for every `cargo
//!    test` invocation in this crate's own CI to depend on.
//!
//!    Domain choices and what's assumed about them:
//!
//!    - `cloudflare.com`: used by `hickory-resolver`'s own upstream test
//!      suite as the canonical "known to validate as DNSSEC Secure" domain
//!      (see `hickory-resolver::resolver::tests::sec_lookup_test`). Cloudflare
//!      also operates a major CDN/TLS product and dogfoods HSTS/modern TLS on
//!      its own marketing domain. Assumed stable: DNSSEC-signed, valid public
//!      cert chain, TLS 1.3, HSTS present.
//!    - `hickory-dns.org`: used by `hickory-resolver`'s own test suite as a
//!      domain that exists but is deliberately *not* DNSSEC-signed (see
//!      `hickory-resolver::resolver::tests::sec_lookup_fails_test`). Assumed
//!      stable: resolves, but DNSSEC-`Insecure`.
//!    - `github.com`: long-standing, well-documented security header policy
//!      (HSTS with a long max-age, `X-Content-Type-Options: nosniff`). Assumed
//!      stable: serves the required baseline header set over HTTPS.

use outpost::config::{CtConfig, HeadersConfig, TlsConfig, TlsVersion};
use outpost::report::Status;
use outpost::{ct, dns, headers, tls};

use std::sync::Arc;

use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------
// Mocked failure cases
// ---------------------------------------------------------------------

#[tokio::test]
async fn headers_check_fails_against_mock_server_missing_required_headers() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).insert_header("content-type", "text/html"))
        .mount(&server)
        .await;

    let cfg = HeadersConfig::default();
    let result = headers::check_url(&format!("{}/", server.uri()), &cfg).await;

    assert_eq!(result.status, Status::Fail);
    assert!(result
        .details
        .iter()
        .any(|d| d.contains("strict-transport-security")));
}

#[tokio::test]
async fn headers_check_passes_against_mock_server_with_full_header_set() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header(
                    "strict-transport-security",
                    "max-age=31536000; includeSubDomains",
                )
                .insert_header("x-content-type-options", "nosniff")
                .insert_header("referrer-policy", "no-referrer")
                .insert_header("x-frame-options", "DENY"),
        )
        .mount(&server)
        .await;

    let cfg = HeadersConfig::default();
    let result = headers::check_url(&format!("{}/", server.uri()), &cfg).await;

    assert_eq!(result.status, Status::Pass);
}

#[tokio::test]
async fn headers_check_skips_on_unreachable_host() {
    let cfg = HeadersConfig::default();
    // Port 1 is reserved/unlikely to have a listener; this should fail fast
    // as a connection error rather than hang or panic.
    let result = headers::check_url("http://127.0.0.1:1/", &cfg).await;
    assert_eq!(result.status, Status::Skip);
}

#[tokio::test]
async fn ct_check_establishes_baseline_on_first_run_without_failing() {
    let server = MockServer::start().await;
    let body = serde_json::json!([
        {
            "id": 1,
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "common_name": "example.com",
            "not_before": "2026-01-01T00:00:00",
            "not_after": "2026-04-01T00:00:00"
        }
    ]);
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;

    let cfg = CtConfig {
        allowed_issuers: vec!["Let's Encrypt".to_string()],
        pinned_fingerprints: vec![],
        fail_on_unknown_issuer: true,
        timeout_seconds: 5,
        crtsh_url: server.uri(),
    };

    let mut state = ct::BaselineState::default();
    let result_first = ct::check("example.com", &cfg, &mut state, None).await;
    assert_eq!(result_first.status, Status::Pass);

    // Re-run against the now-recorded baseline: no new entries this time.
    let result_second = ct::check("example.com", &cfg, &mut state, None).await;
    assert_eq!(result_second.status, Status::Pass);
    assert!(result_second
        .details
        .iter()
        .any(|d| d.contains("no new CT log entries")));
}

#[tokio::test]
async fn ct_check_skips_when_crtsh_is_unreachable() {
    let cfg = CtConfig {
        allowed_issuers: vec!["Let's Encrypt".to_string()],
        pinned_fingerprints: vec![],
        fail_on_unknown_issuer: true,
        timeout_seconds: 2,
        crtsh_url: "http://127.0.0.1:1".to_string(),
    };
    let mut state = ct::BaselineState::default();
    let result = ct::check("example.com", &cfg, &mut state, None).await;
    assert_eq!(result.status, Status::Skip);
}

#[tokio::test]
async fn ct_check_flags_unrecognized_issuer_against_a_seeded_baseline() {
    let server = MockServer::start().await;
    let body = serde_json::json!([
        {
            "id": 1,
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "common_name": "example.com",
            "not_before": "2026-01-01T00:00:00",
            "not_after": "2026-04-01T00:00:00"
        },
        {
            "id": 2,
            "issuer_name": "C=XX, O=Totally Legit CA, CN=Definitely Real",
            "common_name": "example.com",
            "not_before": "2026-05-01T00:00:00",
            "not_after": "2026-08-01T00:00:00"
        }
    ]);
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;

    // Seed the baseline with id=1 already known, so id=2 (the entry with the
    // unrecognized issuer, once we point at `server` below) is the only
    // "new" entry on the real run.
    let seed_server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "id": 1,
                "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
                "common_name": "example.com",
                "not_before": "2026-01-01T00:00:00",
                "not_after": "2026-04-01T00:00:00"
            }
        ])))
        .mount(&seed_server)
        .await;

    let mut state = ct::BaselineState::default();
    let seed_cfg = CtConfig {
        allowed_issuers: vec!["Let's Encrypt".to_string()],
        pinned_fingerprints: vec![],
        fail_on_unknown_issuer: true,
        timeout_seconds: 5,
        crtsh_url: seed_server.uri(),
    };
    let seed_result = ct::check("example.com", &seed_cfg, &mut state, None).await;
    assert_eq!(seed_result.status, Status::Pass);

    let cfg = CtConfig {
        allowed_issuers: vec!["Let's Encrypt".to_string()],
        pinned_fingerprints: vec![],
        fail_on_unknown_issuer: true,
        timeout_seconds: 5,
        crtsh_url: server.uri(),
    };
    let result = ct::check("example.com", &cfg, &mut state, None).await;
    assert_eq!(result.status, Status::Fail);
    assert!(result
        .details
        .iter()
        .any(|d| d.contains("UNRECOGNIZED ISSUER")));
}

/// A local TLS server presenting a certificate `rustls`'s webpki-roots
/// trust store cannot possibly trust (it's self-signed, generated on the
/// fly). This mocks the "unauthorized/rogue certificate" and "interception
/// proxy" failure modes end-to-end through the real TCP + TLS stack, rather
/// than only through the pure `evaluate()` unit tests.
async fn spawn_untrusted_tls_server() -> u16 {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["mocked.invalid".to_string()]).unwrap();
    let cert_der: CertificateDer<'static> = cert.der().clone();
    let key_der: PrivateKeyDer<'static> = PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into();

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _ = acceptor.accept(stream).await;
            });
        }
    });

    addr.port()
}

#[tokio::test]
async fn tls_check_fails_against_self_signed_mock_server() {
    let port = spawn_untrusted_tls_server().await;
    let result = tls::connect_to("mocked.invalid", "127.0.0.1", port).await;
    assert!(result.is_err());

    let cfg = TlsConfig {
        min_version: TlsVersion::Tls12,
        expiry_warning_days: 14,
        allow_weak_ciphers: false,
    };
    let check_result = match result {
        Err(e) => tls::error_to_result("mocked.invalid", e),
        Ok(_) => panic!("expected the self-signed server to be rejected"),
    };
    assert_eq!(check_result.status, Status::Fail);
    let _ = cfg;
}

#[tokio::test]
async fn tls_check_skips_on_connection_refused() {
    // Nothing is listening on this port.
    let result = tls::connect_to("mocked.invalid", "127.0.0.1", 1).await;
    match result {
        Err(e) => {
            let check_result = tls::error_to_result("mocked.invalid", e);
            assert_eq!(check_result.status, Status::Skip);
        }
        Ok(_) => panic!("expected connection refused"),
    }
}

// ---------------------------------------------------------------------
// Live checks against real, stable public domains (opt-in)
// ---------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires unrestricted outbound network (real DNS over TCP+UDP :53, real TLS to :443); run with `cargo test -- --ignored`"]
async fn live_dns_cloudflare_com_is_dnssec_secure() {
    let result = dns::check("cloudflare.com").await;
    assert_eq!(
        result.status,
        Status::Pass,
        "{result:?}",
        result = result.details
    );
}

#[tokio::test]
#[ignore = "requires unrestricted outbound network; run with `cargo test -- --ignored`"]
async fn live_dns_hickory_dns_org_is_dnssec_insecure() {
    let result = dns::check("hickory-dns.org").await;
    assert_eq!(result.status, Status::Fail);
}

#[tokio::test]
#[ignore = "requires unrestricted outbound network; run with `cargo test -- --ignored`"]
async fn live_tls_cloudflare_com_has_valid_modern_chain() {
    let cfg = TlsConfig {
        min_version: TlsVersion::Tls12,
        expiry_warning_days: 14,
        allow_weak_ciphers: false,
    };
    let result = tls::check("cloudflare.com", &cfg).await;
    assert_eq!(result.status, Status::Pass);
}

#[tokio::test]
#[ignore = "requires unrestricted outbound network; run with `cargo test -- --ignored`"]
async fn live_headers_github_com_has_required_baseline() {
    let cfg = HeadersConfig::default();
    let result = headers::check("github.com", &cfg).await;
    assert!(matches!(result.status, Status::Pass | Status::Warn));
}
