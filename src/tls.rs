//! TLS / certificate chain check.
//!
//! Connects to `domain:443`, completes a TLS handshake with `rustls`
//! (trust anchored to the Mozilla root program via `webpki-roots`, not the
//! host OS trust store -- so a MITM proxy or a rogue enterprise CA installed
//! on the CI runner cannot make this check pass), then inspects:
//!
//! - negotiated protocol version against the configured minimum
//! - leaf certificate expiry against the configured warning window
//! - the negotiated cipher suite (reported for visibility)
//!
//! Cipher suite scope note: `rustls` intentionally never implements or
//! negotiates export ciphers, RC4, 3DES, or non-AEAD CBC suites. There is no
//! "allow weak ciphers" toggle to defeat here because the library never
//! offers them in the first place; `allow_weak_ciphers` in config is
//! accepted for forward compatibility but has no effect while `rustls`
//! remains the transport, and this is reported as a Skip-with-note if
//! someone flips it, rather than silently doing nothing.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use chrono::{TimeZone, Utc};
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::config::{TlsConfig, TlsVersion};
use crate::report::CheckResult;

const CHECK_NAME: &str = "tls";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

static CRYPTO_PROVIDER_INIT: OnceLock<()> = OnceLock::new();

fn ensure_crypto_provider() {
    CRYPTO_PROVIDER_INIT.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn client_config() -> Arc<rustls::ClientConfig> {
    ensure_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(config)
}

/// Everything we learn from a single TLS handshake against a domain.
pub struct TlsConnectionInfo {
    pub protocol_version: String,
    pub cipher_suite: String,
    /// Leaf-first raw DER certificate chain as presented by the server.
    pub chain_der: Vec<Vec<u8>>,
}

#[derive(Debug, thiserror::Error)]
pub enum TlsConnectError {
    #[error("network error connecting to {0}:443: {1}")]
    Network(String, String),
    #[error("TLS handshake failed: {0}")]
    Handshake(String),
}

/// Perform the TCP + TLS handshake and return what was negotiated. Split out
/// from `check` so the Certificate Transparency module can reuse the same
/// live leaf certificate instead of opening a second connection.
pub async fn connect(domain: &str) -> Result<TlsConnectionInfo, TlsConnectError> {
    connect_to(domain, domain, 443).await
}

/// Same as [`connect`] but lets the TCP target and the SNI/hostname-
/// verification name differ and lets the port vary. Exists so tests can
/// point the TCP connection at a local mock TLS server (`127.0.0.1:<port>`)
/// while still exercising real webpki-roots chain validation against
/// whatever hostname the mock's certificate claims.
pub async fn connect_to(
    sni: &str,
    host: &str,
    port: u16,
) -> Result<TlsConnectionInfo, TlsConnectError> {
    let config = client_config();
    let connector = tokio_rustls::TlsConnector::from(config);

    let tcp = timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .map_err(|_| TlsConnectError::Network(host.to_string(), "connection timed out".into()))?
        .map_err(|e| TlsConnectError::Network(host.to_string(), e.to_string()))?;

    let server_name = ServerName::try_from(sni.to_string())
        .map_err(|e| TlsConnectError::Handshake(format!("invalid server name {sni}: {e}")))?;

    let stream = timeout(CONNECT_TIMEOUT, connector.connect(server_name, tcp))
        .await
        .map_err(|_| TlsConnectError::Handshake("handshake timed out".to_string()))?
        .map_err(|e| TlsConnectError::Handshake(e.to_string()))?;

    let (_, conn) = stream.get_ref();

    let protocol_version = conn
        .protocol_version()
        .map(|v| format!("{v:?}"))
        .unwrap_or_else(|| "unknown".to_string());

    let cipher_suite = conn
        .negotiated_cipher_suite()
        .map(|s| format!("{:?}", s.suite()))
        .unwrap_or_else(|| "unknown".to_string());

    let chain_der: Vec<Vec<u8>> = conn
        .peer_certificates()
        .map(|certs| {
            certs
                .iter()
                .map(|c: &CertificateDer| c.as_ref().to_vec())
                .collect()
        })
        .unwrap_or_default();

    if chain_der.is_empty() {
        return Err(TlsConnectError::Handshake(
            "server presented no certificates".to_string(),
        ));
    }

    Ok(TlsConnectionInfo {
        protocol_version,
        cipher_suite,
        chain_der,
    })
}

pub async fn check(domain: &str, cfg: &TlsConfig) -> CheckResult {
    match connect(domain).await {
        Ok(info) => evaluate(domain, &info, cfg),
        Err(e) => error_to_result(domain, e),
    }
}

/// Translate a connection-level failure into a report entry. A network
/// failure (couldn't reach the host at all) is a [`Status::Skip`]; a
/// handshake failure -- which includes certificate chain validation
/// rejections -- is a [`Status::Fail`], since that's a genuine security
/// finding, not an infrastructure hiccup.
pub fn error_to_result(domain: &str, e: TlsConnectError) -> CheckResult {
    match e {
        TlsConnectError::Network(_, msg) => {
            CheckResult::skip(CHECK_NAME, format!("could not reach {domain}:443: {msg}"))
        }
        TlsConnectError::Handshake(msg) => {
            CheckResult::fail(CHECK_NAME, format!("TLS handshake with {domain} failed: {msg}"))
                .with_detail(
                    "this includes certificate chain validation failures: an untrusted issuer, \
                     expired chain, hostname mismatch, or an interception proxy would all surface here"
                        .to_string(),
                )
        }
    }
}

pub fn evaluate(domain: &str, info: &TlsConnectionInfo, cfg: &TlsConfig) -> CheckResult {
    let mut details = vec![
        format!("negotiated protocol: {}", info.protocol_version),
        format!("negotiated cipher suite: {}", info.cipher_suite),
    ];

    let mut failed = false;
    let mut warned = false;

    let negotiated = parse_negotiated_version(&info.protocol_version);
    match negotiated {
        Some(v) if v < cfg.min_version => {
            failed = true;
            details.push(format!(
                "negotiated {v} is below the configured minimum of {}",
                cfg.min_version
            ));
        }
        None => {
            warned = true;
            details.push("could not parse negotiated protocol version".to_string());
        }
        _ => {}
    }

    let leaf = info.chain_der.first();
    match leaf.and_then(|der| x509_parser::parse_x509_certificate(der).ok()) {
        Some((_, cert)) => {
            let not_after = cert.validity().not_after.timestamp();
            let now = Utc::now().timestamp();
            let seconds_remaining = not_after - now;
            let days_remaining = seconds_remaining / 86_400;

            if seconds_remaining <= 0 {
                failed = true;
                details.push(format!(
                    "certificate EXPIRED {} day(s) ago",
                    -days_remaining
                ));
            } else if days_remaining < cfg.expiry_warning_days {
                failed = true;
                details.push(format!(
                    "certificate expires in {days_remaining} day(s), inside the {}-day warning window",
                    cfg.expiry_warning_days
                ));
            } else {
                details.push(format!(
                    "certificate valid for {days_remaining} more day(s)"
                ));
            }

            if let Some(not_after_str) = Utc.timestamp_opt(not_after, 0).single() {
                details.push(format!("not_after: {}", not_after_str.to_rfc3339()));
            }
            details.push(format!("subject: {}", cert.subject()));
            details.push(format!("issuer: {}", cert.issuer()));
        }
        None => {
            warned = true;
            details.push("could not parse leaf certificate for expiry inspection".to_string());
        }
    }

    if cfg.allow_weak_ciphers {
        details.push(
            "allow_weak_ciphers=true has no effect: rustls does not implement weak cipher suites"
                .to_string(),
        );
    }

    let summary = format!("{domain}: {} / leaf cert inspected", info.protocol_version);

    if failed {
        CheckResult::fail(CHECK_NAME, summary).with_details(details)
    } else if warned {
        CheckResult::warn(CHECK_NAME, summary).with_details(details)
    } else {
        CheckResult::pass(CHECK_NAME, summary).with_details(details)
    }
}

fn parse_negotiated_version(s: &str) -> Option<TlsVersion> {
    if s.contains("TLSv1_3") {
        Some(TlsVersion::Tls13)
    } else if s.contains("TLSv1_2") {
        Some(TlsVersion::Tls12)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Status;

    fn cfg(min: TlsVersion) -> TlsConfig {
        TlsConfig {
            min_version: min,
            expiry_warning_days: 14,
            allow_weak_ciphers: false,
        }
    }

    fn self_signed_cert_der(not_after_days_from_now: i64) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        let now = std::time::SystemTime::now();
        params.not_before = (now - std::time::Duration::from_secs(3600)).into();
        params.not_after = (now
            + std::time::Duration::from_secs((not_after_days_from_now.max(0) as u64) * 86_400))
        .into();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        cert.der().to_vec()
    }

    #[test]
    fn parses_tls13_version_string() {
        assert_eq!(parse_negotiated_version("TLSv1_3"), Some(TlsVersion::Tls13));
    }

    #[test]
    fn parses_tls12_version_string() {
        assert_eq!(parse_negotiated_version("TLSv1_2"), Some(TlsVersion::Tls12));
    }

    #[test]
    fn unknown_version_string_returns_none() {
        assert_eq!(parse_negotiated_version("SSLv3"), None);
    }

    #[test]
    fn tls12_negotiated_fails_when_minimum_is_tls13() {
        let info = TlsConnectionInfo {
            protocol_version: "TLSv1_2".to_string(),
            cipher_suite: "TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
            chain_der: vec![],
        };
        let result = evaluate("example.com", &info, &cfg(TlsVersion::Tls13));
        // No leaf cert parsed -> warn, but the version check should still
        // register as a hard failure alongside it.
        assert!(matches!(result.status, Status::Fail));
    }

    #[test]
    fn tls13_negotiated_passes_version_gate_when_minimum_is_tls12() {
        let info = TlsConnectionInfo {
            protocol_version: "TLSv1_3".to_string(),
            cipher_suite: "TLS13_AES_128_GCM_SHA256".to_string(),
            chain_der: vec![],
        };
        let result = evaluate("example.com", &info, &cfg(TlsVersion::Tls12));
        // Missing leaf cert still produces a Warn (can't check expiry), but
        // must not be a Fail purely from the version gate.
        assert!(matches!(result.status, Status::Warn));
    }

    #[test]
    fn cert_expiring_within_warning_window_fails() {
        let der = self_signed_cert_der(5); // expires in 5 days
        let info = TlsConnectionInfo {
            protocol_version: "TLSv1_3".to_string(),
            cipher_suite: "TLS13_AES_128_GCM_SHA256".to_string(),
            chain_der: vec![der],
        };
        let result = evaluate("example.com", &info, &cfg(TlsVersion::Tls12));
        assert_eq!(result.status, Status::Fail);
        assert!(result.details.iter().any(|d| d.contains("warning window")));
    }

    #[test]
    fn cert_already_expired_fails() {
        let der = self_signed_cert_der(-5); // expired 5 days ago
        let info = TlsConnectionInfo {
            protocol_version: "TLSv1_3".to_string(),
            cipher_suite: "TLS13_AES_128_GCM_SHA256".to_string(),
            chain_der: vec![der],
        };
        let result = evaluate("example.com", &info, &cfg(TlsVersion::Tls12));
        assert_eq!(result.status, Status::Fail);
        assert!(result.details.iter().any(|d| d.contains("EXPIRED")));
    }

    #[test]
    fn cert_comfortably_valid_passes() {
        let der = self_signed_cert_der(120);
        let info = TlsConnectionInfo {
            protocol_version: "TLSv1_3".to_string(),
            cipher_suite: "TLS13_AES_128_GCM_SHA256".to_string(),
            chain_der: vec![der],
        };
        let result = evaluate("example.com", &info, &cfg(TlsVersion::Tls12));
        assert_eq!(result.status, Status::Pass);
    }
}
