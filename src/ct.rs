//! Certificate Transparency check.
//!
//! Queries the public [crt.sh](https://crt.sh/) CT log aggregator for
//! certificates logged against the domain, diffs the result against a local
//! "last known good" baseline (`state_file` in the config), and flags:
//!
//! - any newly logged certificate issued by a CA outside `allowed_issuers`
//! - the live, currently-served leaf certificate not matching
//!   `pinned_fingerprints`, when that list is non-empty
//!
//! ## Known limitation (documented per the "no half-finished checks" rule)
//!
//! crt.sh is a free, unauthenticated, community-run service with no SLA and
//! no documented rate limit contract; it will occasionally be slow, return
//! 503s, or throttle a burst of CI runs sharing an egress IP. When it can't
//! be reached in time, this check reports [`Status::Skip`], *not* `Pass` --
//! a skip must never be silently treated as "no unauthorized certs found".
//! If your CI needs a hard guarantee here, treat repeated `Skip`s on the CT
//! check as their own alert condition, and consider a paid CT monitoring
//! feed (e.g. Cisco Umbrella, Facebook CT alerts, or a commercial crt.sh
//! mirror) for anything more sensitive than "would like to know eventually".
//!
//! Also note: crt.sh's JSON search API does not return certificate
//! fingerprints, only issuer/subject metadata and log entry ids. Fingerprint
//! pinning in this tool therefore pins against the *live* leaf certificate
//! served over TLS right now (reusing the connection made by the `tls`
//! check), not against every historical CT log entry.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::CtConfig;
use crate::report::CheckResult;

const CHECK_NAME: &str = "ct";

#[derive(Debug, Clone, Deserialize)]
struct CrtShEntry {
    id: i64,
    issuer_name: String,
    #[serde(default)]
    common_name: String,
    not_before: String,
    not_after: String,
}

/// Baseline state persisted between runs, keyed by domain.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BaselineState {
    #[serde(default)]
    domains: BTreeMap<String, DomainBaseline>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct DomainBaseline {
    #[serde(default)]
    known_crtsh_ids: BTreeSet<i64>,
    last_checked: Option<chrono::DateTime<Utc>>,
}

impl BaselineState {
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(raw) => serde_json::from_str(&raw).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    fn known_ids(&self, domain: &str) -> BTreeSet<i64> {
        self.domains
            .get(domain)
            .map(|d| d.known_crtsh_ids.clone())
            .unwrap_or_default()
    }

    fn record(&mut self, domain: &str, ids: BTreeSet<i64>) {
        self.domains.insert(
            domain.to_string(),
            DomainBaseline {
                known_crtsh_ids: ids,
                last_checked: Some(Utc::now()),
            },
        );
    }
}

async fn fetch_entries(domain: &str, cfg: &CtConfig) -> Result<Vec<CrtShEntry>, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(cfg.timeout_seconds))
        .user_agent(concat!("outpost/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())?;

    let url = format!(
        "{}/?q={domain}&output=json",
        cfg.crtsh_url.trim_end_matches('/')
    );

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("request to crt.sh failed: {e}"))?;

    if !response.status().is_success() {
        return Err(format!("crt.sh returned HTTP {}", response.status()));
    }

    response
        .json::<Vec<CrtShEntry>>()
        .await
        .map_err(|e| format!("could not parse crt.sh response: {e}"))
}

/// The live leaf certificate's SHA-256 fingerprint, computed by `tls::connect`.
pub fn fingerprint_sha256(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    hex::encode(digest)
}

pub async fn check(
    domain: &str,
    cfg: &CtConfig,
    state: &mut BaselineState,
    live_leaf_der: Option<&[u8]>,
) -> CheckResult {
    let entries = match fetch_entries(domain, cfg).await {
        Ok(e) => e,
        Err(msg) => {
            return CheckResult::skip(
                CHECK_NAME,
                format!("could not query CT logs for {domain}: {msg}"),
            );
        }
    };

    let known_ids = state.known_ids(domain);
    let live_fingerprint = live_leaf_der.map(fingerprint_sha256);

    let result = evaluate(
        domain,
        &entries,
        &known_ids,
        cfg,
        live_fingerprint.as_deref(),
    );

    let all_ids: BTreeSet<i64> = entries.iter().map(|e| e.id).collect();
    // Only advance the baseline forward; never shrink it based on a single
    // (possibly partial/rate-limited) query.
    let merged: BTreeSet<i64> = known_ids.union(&all_ids).copied().collect();
    state.record(domain, merged);

    result
}

fn evaluate(
    domain: &str,
    entries: &[CrtShEntry],
    known_ids: &BTreeSet<i64>,
    cfg: &CtConfig,
    live_fingerprint: Option<&str>,
) -> CheckResult {
    let mut details = Vec::new();
    let mut failed = false;
    let mut warned = false;

    let is_first_run = known_ids.is_empty();
    let new_entries: Vec<&CrtShEntry> = entries
        .iter()
        .filter(|e| !known_ids.contains(&e.id))
        .collect();

    if is_first_run {
        details.push(format!(
            "no prior baseline for {domain}; recording {} known CT log entries as the new baseline",
            entries.len()
        ));
    } else if new_entries.is_empty() {
        details.push(format!(
            "no new CT log entries since last run ({} known)",
            known_ids.len()
        ));
    } else {
        details.push(format!(
            "{} new CT log entry(ies) since last run",
            new_entries.len()
        ));

        if cfg.allowed_issuers.is_empty() {
            warned = true;
            details.push(
                "no ct.allowed_issuers configured; cannot distinguish an authorized renewal from \
                 an unauthorized issuance -- listing new entries for manual review"
                    .to_string(),
            );
            for e in &new_entries {
                details.push(format!(
                    "  new: id={} cn={} issuer={} not_before={} not_after={}",
                    e.id, e.common_name, e.issuer_name, e.not_before, e.not_after
                ));
            }
        } else {
            for e in &new_entries {
                let trusted = cfg.allowed_issuers.iter().any(|allowed| {
                    e.issuer_name
                        .to_lowercase()
                        .contains(&allowed.to_lowercase())
                });
                if trusted {
                    details.push(format!(
                        "new cert from trusted issuer: id={} cn={} issuer={}",
                        e.id, e.common_name, e.issuer_name
                    ));
                } else if cfg.fail_on_unknown_issuer {
                    failed = true;
                    details.push(format!(
                        "UNRECOGNIZED ISSUER: id={} cn={} issuer='{}' is not in the allowed_issuers list -- \
                         possible unauthorized certificate issuance",
                        e.id, e.common_name, e.issuer_name
                    ));
                } else {
                    warned = true;
                    details.push(format!(
                        "unrecognized issuer (not failing, fail_on_unknown_issuer=false): id={} cn={} issuer='{}'",
                        e.id, e.common_name, e.issuer_name
                    ));
                }
            }
        }
    }

    if !cfg.pinned_fingerprints.is_empty() {
        match live_fingerprint {
            Some(fp) => {
                let pinned = cfg
                    .pinned_fingerprints
                    .iter()
                    .any(|p| p.eq_ignore_ascii_case(fp));
                if pinned {
                    details.push(format!(
                        "live certificate fingerprint {fp} matches a pinned fingerprint"
                    ));
                } else {
                    failed = true;
                    details.push(format!(
                        "live certificate fingerprint {fp} does NOT match any pinned_fingerprints entry"
                    ));
                }
            }
            None => {
                warned = true;
                details.push(
                    "pinned_fingerprints configured but no live leaf certificate was available to compare \
                     (the tls check may have failed or be disabled)"
                        .to_string(),
                );
            }
        }
    }

    let summary = format!(
        "{domain}: {} CT log entries known, {} new",
        known_ids.len().max(entries.len()),
        new_entries.len()
    );

    if failed {
        CheckResult::fail(CHECK_NAME, summary).with_details(details)
    } else if warned {
        CheckResult::warn(CHECK_NAME, summary).with_details(details)
    } else {
        CheckResult::pass(CHECK_NAME, summary).with_details(details)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Status;

    fn cfg(allowed: Vec<&str>) -> CtConfig {
        CtConfig {
            allowed_issuers: allowed.into_iter().map(String::from).collect(),
            pinned_fingerprints: Vec::new(),
            fail_on_unknown_issuer: true,
            timeout_seconds: 15,
            crtsh_url: "https://crt.sh".to_string(),
        }
    }

    fn entry(id: i64, issuer: &str) -> CrtShEntry {
        CrtShEntry {
            id,
            issuer_name: issuer.to_string(),
            common_name: "example.com".to_string(),
            not_before: "2026-01-01T00:00:00".to_string(),
            not_after: "2026-04-01T00:00:00".to_string(),
        }
    }

    #[test]
    fn first_run_establishes_baseline_without_failing() {
        let entries = vec![entry(1, "C=US, O=Let's Encrypt, CN=R3")];
        let known = BTreeSet::new();
        let result = evaluate(
            "example.com",
            &entries,
            &known,
            &cfg(vec!["Let's Encrypt"]),
            None,
        );
        assert_eq!(result.status, Status::Pass);
    }

    #[test]
    fn new_entry_from_allowed_issuer_passes() {
        let entries = vec![
            entry(1, "C=US, O=Let's Encrypt, CN=R3"),
            entry(2, "C=US, O=Let's Encrypt, CN=R3"),
        ];
        let mut known = BTreeSet::new();
        known.insert(1);
        let result = evaluate(
            "example.com",
            &entries,
            &known,
            &cfg(vec!["Let's Encrypt"]),
            None,
        );
        assert_eq!(result.status, Status::Pass);
    }

    #[test]
    fn new_entry_from_unknown_issuer_fails() {
        let entries = vec![
            entry(1, "C=US, O=Let's Encrypt, CN=R3"),
            entry(2, "C=CN, O=Suspicious CA, CN=X1"),
        ];
        let mut known = BTreeSet::new();
        known.insert(1);
        let result = evaluate(
            "example.com",
            &entries,
            &known,
            &cfg(vec!["Let's Encrypt"]),
            None,
        );
        assert_eq!(result.status, Status::Fail);
        assert!(result
            .details
            .iter()
            .any(|d| d.contains("UNRECOGNIZED ISSUER")));
    }

    #[test]
    fn no_allowlist_configured_warns_instead_of_failing_or_passing_blindly() {
        let entries = vec![
            entry(1, "C=US, O=Let's Encrypt, CN=R3"),
            entry(2, "C=CN, O=Suspicious CA, CN=X1"),
        ];
        let mut known = BTreeSet::new();
        known.insert(1);
        let result = evaluate("example.com", &entries, &known, &cfg(vec![]), None);
        assert_eq!(result.status, Status::Warn);
    }

    #[test]
    fn pinned_fingerprint_mismatch_fails() {
        let entries = vec![entry(1, "C=US, O=Let's Encrypt, CN=R3")];
        let mut known = BTreeSet::new();
        known.insert(1);
        let mut c = cfg(vec!["Let's Encrypt"]);
        c.pinned_fingerprints = vec!["deadbeef".to_string()];
        let result = evaluate("example.com", &entries, &known, &c, Some("cafebabe"));
        assert_eq!(result.status, Status::Fail);
    }

    #[test]
    fn pinned_fingerprint_match_passes() {
        let entries = vec![entry(1, "C=US, O=Let's Encrypt, CN=R3")];
        let mut known = BTreeSet::new();
        known.insert(1);
        let mut c = cfg(vec!["Let's Encrypt"]);
        c.pinned_fingerprints = vec!["cafebabe".to_string()];
        let result = evaluate("example.com", &entries, &known, &c, Some("cafebabe"));
        assert_eq!(result.status, Status::Pass);
    }

    #[test]
    fn baseline_state_roundtrips_through_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("outpost.state.json");
        let mut state = BaselineState::default();
        let mut ids = BTreeSet::new();
        ids.insert(1);
        ids.insert(2);
        state.record("example.com", ids.clone());
        state.save(&path).unwrap();

        let loaded = BaselineState::load(&path);
        assert_eq!(loaded.known_ids("example.com"), ids);
    }

    #[test]
    fn fingerprint_is_deterministic_sha256_hex() {
        let fp1 = fingerprint_sha256(b"hello");
        let fp2 = fingerprint_sha256(b"hello");
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 64);
    }
}
