//! Configuration file (`outpost.toml`) schema, parsing, and per-domain
//! default/override resolution.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Top-level `outpost.toml` document.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Where CT baseline state ("last known good" fingerprints) is persisted.
    #[serde(default = "default_state_file")]
    pub state_file: PathBuf,

    /// Defaults applied to every domain unless overridden.
    #[serde(default)]
    pub defaults: Defaults,

    /// Domains to scan.
    #[serde(default, rename = "domains")]
    pub domains: Vec<DomainEntry>,
}

fn default_state_file() -> PathBuf {
    PathBuf::from("outpost.state.json")
}

impl Default for Config {
    fn default() -> Self {
        Self {
            state_file: default_state_file(),
            defaults: Defaults::default(),
            domains: Vec::new(),
        }
    }
}

impl Config {
    /// Load and parse a config file from disk.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        let cfg: Config = toml::from_str(&raw)
            .with_context(|| format!("parsing config file {}", path.display()))?;
        if cfg.domains.is_empty() {
            anyhow::bail!(
                "config file {} defines no [[domains]] entries",
                path.display()
            );
        }
        Ok(cfg)
    }

    /// Resolve the effective, fully-populated configuration for every domain.
    pub fn effective_domains(&self) -> Vec<EffectiveDomain> {
        self.domains
            .iter()
            .map(|d| d.resolve(&self.defaults))
            .collect()
    }
}

/// Which checks run by default / per-domain.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChecksEnabled {
    #[serde(default = "default_true")]
    pub dns: bool,
    #[serde(default = "default_true")]
    pub tls: bool,
    #[serde(default = "default_true")]
    pub ct: bool,
    #[serde(default = "default_true")]
    pub headers: bool,
}

fn default_true() -> bool {
    true
}

impl Default for ChecksEnabled {
    fn default() -> Self {
        Self {
            dns: true,
            tls: true,
            ct: true,
            headers: true,
        }
    }
}

/// Partial override of [`ChecksEnabled`] for a single domain.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChecksOverride {
    pub dns: Option<bool>,
    pub tls: Option<bool>,
    pub ct: Option<bool>,
    pub headers: Option<bool>,
}

/// Minimum acceptable TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsVersion {
    #[serde(rename = "1.2")]
    Tls12,
    #[serde(rename = "1.3")]
    Tls13,
}

impl std::fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tls12 => write!(f, "TLS 1.2"),
            Self::Tls13 => write!(f, "TLS 1.3"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    #[serde(default = "default_tls_min_version")]
    pub min_version: TlsVersion,
    #[serde(default = "default_expiry_warning_days")]
    pub expiry_warning_days: i64,
    #[serde(default)]
    pub allow_weak_ciphers: bool,
}

fn default_tls_min_version() -> TlsVersion {
    TlsVersion::Tls12
}

fn default_expiry_warning_days() -> i64 {
    14
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            min_version: default_tls_min_version(),
            expiry_warning_days: default_expiry_warning_days(),
            allow_weak_ciphers: false,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsOverride {
    pub min_version: Option<TlsVersion>,
    pub expiry_warning_days: Option<i64>,
    pub allow_weak_ciphers: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeadersConfig {
    /// Header names (lowercase) that MUST be present.
    #[serde(default = "default_required_headers")]
    pub require: Vec<String>,
    /// Minimum `max-age` accepted for Strict-Transport-Security.
    #[serde(default = "default_hsts_max_age")]
    pub hsts_min_max_age_seconds: i64,
    #[serde(default = "default_true")]
    pub hsts_require_include_subdomains: bool,
    #[serde(default)]
    pub hsts_require_preload: bool,
    /// Require either X-Frame-Options or a CSP `frame-ancestors` directive.
    #[serde(default = "default_true")]
    pub require_frame_protection: bool,
    #[serde(default = "default_http_timeout")]
    pub timeout_seconds: u64,
}

fn default_required_headers() -> Vec<String> {
    vec![
        "strict-transport-security".to_string(),
        "x-content-type-options".to_string(),
        "referrer-policy".to_string(),
    ]
}

fn default_hsts_max_age() -> i64 {
    15_552_000 // 180 days
}

fn default_http_timeout() -> u64 {
    10
}

impl Default for HeadersConfig {
    fn default() -> Self {
        Self {
            require: default_required_headers(),
            hsts_min_max_age_seconds: default_hsts_max_age(),
            hsts_require_include_subdomains: true,
            hsts_require_preload: false,
            require_frame_protection: true,
            timeout_seconds: default_http_timeout(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeadersOverride {
    pub require: Option<Vec<String>>,
    pub hsts_min_max_age_seconds: Option<i64>,
    pub hsts_require_include_subdomains: Option<bool>,
    pub hsts_require_preload: Option<bool>,
    pub require_frame_protection: Option<bool>,
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CtConfig {
    /// CA organization names (as they appear in crt.sh `issuer_name`) that are
    /// allowed to issue certificates for this domain.
    #[serde(default)]
    pub allowed_issuers: Vec<String>,
    /// SHA-256 leaf certificate fingerprints (hex, no colons) that are always
    /// trusted regardless of issuer.
    #[serde(default)]
    pub pinned_fingerprints: Vec<String>,
    /// Fail the check when a logged cert's issuer isn't in `allowed_issuers`.
    #[serde(default = "default_true")]
    pub fail_on_unknown_issuer: bool,
    #[serde(default = "default_crtsh_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_crtsh_url")]
    pub crtsh_url: String,
}

fn default_crtsh_timeout() -> u64 {
    15
}

fn default_crtsh_url() -> String {
    "https://crt.sh/".to_string()
}

impl Default for CtConfig {
    fn default() -> Self {
        Self {
            allowed_issuers: Vec::new(),
            pinned_fingerprints: Vec::new(),
            fail_on_unknown_issuer: true,
            timeout_seconds: default_crtsh_timeout(),
            crtsh_url: default_crtsh_url(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CtOverride {
    pub allowed_issuers: Option<Vec<String>>,
    pub pinned_fingerprints: Option<Vec<String>>,
    pub fail_on_unknown_issuer: Option<bool>,
    pub timeout_seconds: Option<u64>,
    pub crtsh_url: Option<String>,
}

/// `[defaults]` table.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    #[serde(default)]
    pub checks: ChecksEnabled,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub headers: HeadersConfig,
    #[serde(default)]
    pub ct: CtConfig,
}

/// One `[[domains]]` entry: a domain name plus optional per-check overrides.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DomainEntry {
    pub name: String,
    #[serde(default)]
    pub checks: ChecksOverride,
    #[serde(default)]
    pub tls: TlsOverride,
    #[serde(default)]
    pub headers: HeadersOverride,
    #[serde(default)]
    pub ct: CtOverride,
}

impl DomainEntry {
    fn resolve(&self, defaults: &Defaults) -> EffectiveDomain {
        EffectiveDomain {
            name: self.name.clone(),
            checks: ChecksEnabled {
                dns: self.checks.dns.unwrap_or(defaults.checks.dns),
                tls: self.checks.tls.unwrap_or(defaults.checks.tls),
                ct: self.checks.ct.unwrap_or(defaults.checks.ct),
                headers: self.checks.headers.unwrap_or(defaults.checks.headers),
            },
            tls: TlsConfig {
                min_version: self.tls.min_version.unwrap_or(defaults.tls.min_version),
                expiry_warning_days: self
                    .tls
                    .expiry_warning_days
                    .unwrap_or(defaults.tls.expiry_warning_days),
                allow_weak_ciphers: self
                    .tls
                    .allow_weak_ciphers
                    .unwrap_or(defaults.tls.allow_weak_ciphers),
            },
            headers: HeadersConfig {
                require: self
                    .headers
                    .require
                    .clone()
                    .unwrap_or_else(|| defaults.headers.require.clone()),
                hsts_min_max_age_seconds: self
                    .headers
                    .hsts_min_max_age_seconds
                    .unwrap_or(defaults.headers.hsts_min_max_age_seconds),
                hsts_require_include_subdomains: self
                    .headers
                    .hsts_require_include_subdomains
                    .unwrap_or(defaults.headers.hsts_require_include_subdomains),
                hsts_require_preload: self
                    .headers
                    .hsts_require_preload
                    .unwrap_or(defaults.headers.hsts_require_preload),
                require_frame_protection: self
                    .headers
                    .require_frame_protection
                    .unwrap_or(defaults.headers.require_frame_protection),
                timeout_seconds: self
                    .headers
                    .timeout_seconds
                    .unwrap_or(defaults.headers.timeout_seconds),
            },
            ct: CtConfig {
                allowed_issuers: self
                    .ct
                    .allowed_issuers
                    .clone()
                    .unwrap_or_else(|| defaults.ct.allowed_issuers.clone()),
                pinned_fingerprints: self
                    .ct
                    .pinned_fingerprints
                    .clone()
                    .unwrap_or_else(|| defaults.ct.pinned_fingerprints.clone()),
                fail_on_unknown_issuer: self
                    .ct
                    .fail_on_unknown_issuer
                    .unwrap_or(defaults.ct.fail_on_unknown_issuer),
                timeout_seconds: self
                    .ct
                    .timeout_seconds
                    .unwrap_or(defaults.ct.timeout_seconds),
                crtsh_url: self
                    .ct
                    .crtsh_url
                    .clone()
                    .unwrap_or_else(|| defaults.ct.crtsh_url.clone()),
            },
        }
    }
}

/// Fully resolved configuration for a single domain, ready to hand to the
/// check modules.
#[derive(Debug, Clone)]
pub struct EffectiveDomain {
    pub name: String,
    pub checks: ChecksEnabled,
    pub tls: TlsConfig,
    pub headers: HeadersConfig,
    pub ct: CtConfig,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config() {
        let toml_str = r#"
            [[domains]]
            name = "example.com"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.domains.len(), 1);
        assert_eq!(cfg.domains[0].name, "example.com");
        let effective = cfg.effective_domains();
        assert!(effective[0].checks.dns);
        assert!(effective[0].checks.tls);
        assert!(effective[0].checks.ct);
        assert!(effective[0].checks.headers);
        assert_eq!(effective[0].tls.min_version, TlsVersion::Tls12);
        assert_eq!(effective[0].tls.expiry_warning_days, 14);
    }

    #[test]
    fn per_domain_overrides_win_over_defaults() {
        let toml_str = r#"
            [defaults.tls]
            min_version = "1.2"
            expiry_warning_days = 14

            [defaults.ct]
            allowed_issuers = ["Let's Encrypt"]

            [[domains]]
            name = "strict.example.com"
            [domains.tls]
            min_version = "1.3"
            [domains.checks]
            ct = false
            [domains.ct]
            allowed_issuers = ["DigiCert Inc"]

            [[domains]]
            name = "default.example.com"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        let effective = cfg.effective_domains();

        let strict = effective
            .iter()
            .find(|d| d.name == "strict.example.com")
            .unwrap();
        assert_eq!(strict.tls.min_version, TlsVersion::Tls13);
        assert!(!strict.checks.ct);
        assert_eq!(strict.ct.allowed_issuers, vec!["DigiCert Inc".to_string()]);

        let default_domain = effective
            .iter()
            .find(|d| d.name == "default.example.com")
            .unwrap();
        assert_eq!(default_domain.tls.min_version, TlsVersion::Tls12);
        assert!(default_domain.checks.ct);
        assert_eq!(
            default_domain.ct.allowed_issuers,
            vec!["Let's Encrypt".to_string()]
        );
    }

    #[test]
    fn rejects_config_with_no_domains() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("outpost.toml");
        std::fs::write(&path, "state_file = \"outpost.state.json\"\n").unwrap();
        let err = Config::load(&path).unwrap_err();
        assert!(err.to_string().contains("no [[domains]]"));
    }

    #[test]
    fn rejects_unknown_fields() {
        let toml_str = r#"
            [[domains]]
            name = "example.com"
            not_a_real_field = true
        "#;
        assert!(toml::from_str::<Config>(toml_str).is_err());
    }
}
