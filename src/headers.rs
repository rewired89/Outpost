//! HTTP security header check.
//!
//! Fetches the domain over HTTPS and verifies the presence and, for a few
//! well-known headers, the reasonableness of the value of browser-enforced
//! security policy headers: `Strict-Transport-Security`,
//! `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`
//! (or a CSP `frame-ancestors` directive), `Referrer-Policy`, and
//! `Permissions-Policy`.
//!
//! Scope note: CSP is checked for *presence* and for a `frame-ancestors`
//! directive only. We deliberately do not attempt to grade overall CSP
//! policy strength (e.g. flagging `unsafe-inline` in `script-src`) -- that
//! requires judgment calls that vary per site and would silently degrade
//! into a lint nobody trusts. Treat CSP presence as a signal, not a full audit.

use reqwest::header::HeaderMap;
use std::time::Duration;

use crate::config::HeadersConfig;
use crate::report::CheckResult;

const CHECK_NAME: &str = "headers";

pub async fn check(domain: &str, cfg: &HeadersConfig) -> CheckResult {
    check_url(&format!("https://{domain}/"), cfg).await
}

/// Same as [`check`] but against an arbitrary URL rather than assuming
/// `https://{domain}/`. Exists so tests (and this module's own integration
/// tests) can point it at a local mock HTTP server instead of a real
/// HTTPS-only domain.
pub async fn check_url(url: &str, cfg: &HeadersConfig) -> CheckResult {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(cfg.timeout_seconds))
        .user_agent(concat!("outpost/", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return CheckResult::skip(CHECK_NAME, format!("could not build HTTP client: {e}"))
        }
    };

    let response = match client.get(url).send().await {
        Ok(r) => r,
        Err(e) => {
            return CheckResult::skip(CHECK_NAME, format!("could not fetch {url}: {e}"));
        }
    };

    evaluate(response.headers(), cfg)
}

/// Pure, network-free evaluation of a header set against the configured
/// requirements. Kept separate from `check` so it can be unit tested with
/// hand-built `HeaderMap`s instead of live HTTP requests.
pub fn evaluate(headers: &HeaderMap, cfg: &HeadersConfig) -> CheckResult {
    let mut details: Vec<String> = Vec::new();
    let mut failed = false;
    let mut warned = false;

    for required in &cfg.require {
        let name = required.to_lowercase();
        if get_header(headers, &name).is_none() {
            failed = true;
            details.push(format!("missing required header: {name}"));
        }
    }

    if let Some(hsts) = get_header(headers, "strict-transport-security") {
        match evaluate_hsts(&hsts, cfg) {
            Ok(notes) => details.extend(notes),
            Err(issue) => {
                failed = true;
                details.push(issue);
            }
        }
    }

    if let Some(xcto) = get_header(headers, "x-content-type-options") {
        if xcto.trim().to_lowercase() != "nosniff" {
            failed = true;
            details.push(format!(
                "x-content-type-options has non-standard value '{xcto}' (expected 'nosniff')"
            ));
        }
    }

    if let Some(rp) = get_header(headers, "referrer-policy") {
        let value = rp.trim().to_lowercase();
        if value == "unsafe-url" {
            warned = true;
            details.push(
                "referrer-policy is 'unsafe-url', which leaks the full referrer cross-origin"
                    .to_string(),
            );
        }
    }

    if cfg.require_frame_protection {
        let xfo = get_header(headers, "x-frame-options");
        let csp = get_header(headers, "content-security-policy");
        let has_frame_ancestors = csp
            .as_deref()
            .map(|v| v.to_lowercase().contains("frame-ancestors"))
            .unwrap_or(false);
        let xfo_ok = xfo
            .as_deref()
            .map(|v| {
                let v = v.trim().to_lowercase();
                v == "deny" || v == "sameorigin"
            })
            .unwrap_or(false);

        if !xfo_ok && !has_frame_ancestors {
            failed = true;
            details.push(
                "no clickjacking protection: missing X-Frame-Options (DENY/SAMEORIGIN) and no CSP frame-ancestors directive"
                    .to_string(),
            );
        }
    }

    let status_summary = format!(
        "{}/{} required headers present",
        present_count(headers, cfg),
        cfg.require.len()
    );

    if failed {
        CheckResult::fail(CHECK_NAME, status_summary).with_details(details)
    } else if warned {
        CheckResult::warn(CHECK_NAME, status_summary).with_details(details)
    } else {
        CheckResult::pass(CHECK_NAME, status_summary).with_details(details)
    }
}

/// A concrete header value to add or correct, derived from the same rules
/// `evaluate` checks against. This is what `outpost fix` writes into a
/// `_headers` file and proposes as a pull request -- deliberately a
/// structured value, not a re-parse of `evaluate`'s prose `details`, so a
/// wording change in one can't silently break the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderFix {
    pub header: String,
    pub value: String,
    pub reason: String,
}

/// Pure, network-free: given the headers a site is currently serving and the
/// configured requirements, what exact header lines would satisfy them.
/// Only covers headers with one unambiguous, safe default value -- this
/// deliberately does not attempt to suggest a `Content-Security-Policy`,
/// since a safe CSP is specific to each site's actual scripts/styles/frames
/// and a wrong guess would break the site rather than secure it.
pub fn suggest_fixes(headers: &HeaderMap, cfg: &HeadersConfig) -> Vec<HeaderFix> {
    let mut fixes = Vec::new();

    let hsts_ok = get_header(headers, "strict-transport-security")
        .map(|v| evaluate_hsts(&v, cfg).is_ok())
        .unwrap_or(false);
    if !hsts_ok {
        let mut directives = vec![format!(
            "max-age={}",
            cfg.hsts_min_max_age_seconds.max(15_552_000)
        )];
        if cfg.hsts_require_include_subdomains {
            directives.push("includeSubDomains".to_string());
        }
        if cfg.hsts_require_preload {
            directives.push("preload".to_string());
        }
        fixes.push(HeaderFix {
            header: "Strict-Transport-Security".to_string(),
            value: directives.join("; "),
            reason: "forces HTTPS on every future visit, closing the window for a downgrade or interception attack".to_string(),
        });
    }

    let xcto_required = cfg
        .require
        .iter()
        .any(|h| h.eq_ignore_ascii_case("x-content-type-options"));
    let xcto_ok = get_header(headers, "x-content-type-options")
        .map(|v| v.trim().eq_ignore_ascii_case("nosniff"))
        .unwrap_or(false);
    if xcto_required && !xcto_ok {
        fixes.push(HeaderFix {
            header: "X-Content-Type-Options".to_string(),
            value: "nosniff".to_string(),
            reason: "stops the browser from guessing content types in a way that can turn an upload into executable script".to_string(),
        });
    }

    let rp_required = cfg
        .require
        .iter()
        .any(|h| h.eq_ignore_ascii_case("referrer-policy"));
    let rp = get_header(headers, "referrer-policy");
    let rp_unsafe = rp
        .as_deref()
        .map(|v| v.trim().eq_ignore_ascii_case("unsafe-url"))
        .unwrap_or(false);
    if (rp_required && rp.is_none()) || rp_unsafe {
        fixes.push(HeaderFix {
            header: "Referrer-Policy".to_string(),
            value: "strict-origin-when-cross-origin".to_string(),
            reason: "stops the full URL (which can contain sensitive query params) from leaking to third-party sites".to_string(),
        });
    }

    if cfg.require_frame_protection {
        let xfo_ok = get_header(headers, "x-frame-options")
            .map(|v| {
                let v = v.trim().to_lowercase();
                v == "deny" || v == "sameorigin"
            })
            .unwrap_or(false);
        let csp_has_frame_ancestors = get_header(headers, "content-security-policy")
            .map(|v| v.to_lowercase().contains("frame-ancestors"))
            .unwrap_or(false);
        if !xfo_ok && !csp_has_frame_ancestors {
            fixes.push(HeaderFix {
                header: "X-Frame-Options".to_string(),
                value: "DENY".to_string(),
                reason: "blocks the page from being embedded in another site's frame, closing the door on clickjacking".to_string(),
            });
        }
    }

    fixes
}

fn present_count(headers: &HeaderMap, cfg: &HeadersConfig) -> usize {
    cfg.require
        .iter()
        .filter(|h| get_header(headers, &h.to_lowercase()).is_some())
        .count()
}

fn get_header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Returns extra informational notes on success, or an error message describing
/// why the HSTS header fails the configured policy.
fn evaluate_hsts(value: &str, cfg: &HeadersConfig) -> Result<Vec<String>, String> {
    let mut max_age: Option<i64> = None;
    let mut include_subdomains = false;
    let mut preload = false;

    for part in value.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("max-age=") {
            max_age = v.trim().parse::<i64>().ok();
        } else if part.eq_ignore_ascii_case("includeSubDomains") {
            include_subdomains = true;
        } else if part.eq_ignore_ascii_case("preload") {
            preload = true;
        }
    }

    let max_age = match max_age {
        Some(v) => v,
        None => return Err("strict-transport-security has no parseable max-age".to_string()),
    };

    if max_age < cfg.hsts_min_max_age_seconds {
        return Err(format!(
            "strict-transport-security max-age={max_age} is below the required minimum of {}",
            cfg.hsts_min_max_age_seconds
        ));
    }

    if cfg.hsts_require_include_subdomains && !include_subdomains {
        return Err("strict-transport-security is missing includeSubDomains".to_string());
    }

    if cfg.hsts_require_preload && !preload {
        return Err("strict-transport-security is missing preload".to_string());
    }

    Ok(vec![format!(
        "hsts ok: max-age={max_age}, includeSubDomains={include_subdomains}, preload={preload}"
    )])
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    fn cfg() -> HeadersConfig {
        HeadersConfig {
            require: vec![
                "strict-transport-security".to_string(),
                "x-content-type-options".to_string(),
                "referrer-policy".to_string(),
            ],
            hsts_min_max_age_seconds: 15_552_000,
            hsts_require_include_subdomains: true,
            hsts_require_preload: false,
            require_frame_protection: true,
            timeout_seconds: 10,
        }
    }

    fn good_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
        );
        h.insert(
            "x-content-type-options",
            HeaderValue::from_static("nosniff"),
        );
        h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
        h.insert("x-frame-options", HeaderValue::from_static("DENY"));
        h.insert(
            "content-security-policy",
            HeaderValue::from_static("default-src 'self'; frame-ancestors 'none'"),
        );
        h
    }

    #[test]
    fn passes_with_full_header_set() {
        let result = evaluate(&good_headers(), &cfg());
        assert_eq!(result.status, crate::report::Status::Pass);
    }

    #[test]
    fn fails_when_hsts_missing() {
        let mut headers = good_headers();
        headers.remove("strict-transport-security");
        let result = evaluate(&headers, &cfg());
        assert_eq!(result.status, crate::report::Status::Fail);
        assert!(result
            .details
            .iter()
            .any(|d| d.contains("strict-transport-security")));
    }

    #[test]
    fn fails_when_hsts_max_age_too_low() {
        let mut headers = good_headers();
        headers.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=60"),
        );
        let result = evaluate(&headers, &cfg());
        assert_eq!(result.status, crate::report::Status::Fail);
        assert!(result
            .details
            .iter()
            .any(|d| d.contains("below the required minimum")));
    }

    #[test]
    fn fails_when_no_clickjacking_protection() {
        let mut headers = good_headers();
        headers.remove("x-frame-options");
        headers.remove("content-security-policy");
        let result = evaluate(&headers, &cfg());
        assert_eq!(result.status, crate::report::Status::Fail);
        assert!(result.details.iter().any(|d| d.contains("clickjacking")));
    }

    #[test]
    fn frame_ancestors_in_csp_satisfies_frame_protection_without_xfo() {
        let mut headers = good_headers();
        headers.remove("x-frame-options");
        let result = evaluate(&headers, &cfg());
        assert_eq!(result.status, crate::report::Status::Pass);
    }

    #[test]
    fn warns_on_unsafe_url_referrer_policy() {
        let mut headers = good_headers();
        headers.insert("referrer-policy", HeaderValue::from_static("unsafe-url"));
        let result = evaluate(&headers, &cfg());
        assert_eq!(result.status, crate::report::Status::Warn);
    }

    #[test]
    fn fails_on_non_nosniff_content_type_options() {
        let mut headers = good_headers();
        headers.insert("x-content-type-options", HeaderValue::from_static("sniff"));
        let result = evaluate(&headers, &cfg());
        assert_eq!(result.status, crate::report::Status::Fail);
    }

    #[test]
    fn suggest_fixes_is_empty_for_a_fully_compliant_header_set() {
        let fixes = suggest_fixes(&good_headers(), &cfg());
        assert!(fixes.is_empty());
    }

    #[test]
    fn suggest_fixes_proposes_hsts_when_missing() {
        let mut headers = good_headers();
        headers.remove("strict-transport-security");
        let fixes = suggest_fixes(&headers, &cfg());
        let hsts = fixes
            .iter()
            .find(|f| f.header == "Strict-Transport-Security")
            .expect("expected an HSTS fix");
        assert!(hsts.value.contains("max-age=15552000"));
        assert!(hsts.value.contains("includeSubDomains"));
    }

    #[test]
    fn suggest_fixes_proposes_xfo_when_no_clickjacking_protection() {
        let mut headers = good_headers();
        headers.remove("x-frame-options");
        headers.remove("content-security-policy");
        let fixes = suggest_fixes(&headers, &cfg());
        let xfo = fixes
            .iter()
            .find(|f| f.header == "X-Frame-Options")
            .expect("expected an X-Frame-Options fix");
        assert_eq!(xfo.value, "DENY");
    }

    #[test]
    fn suggest_fixes_does_not_touch_frame_protection_when_csp_already_covers_it() {
        let mut headers = good_headers();
        headers.remove("x-frame-options");
        // content-security-policy with frame-ancestors is still present here.
        let fixes = suggest_fixes(&headers, &cfg());
        assert!(!fixes.iter().any(|f| f.header == "X-Frame-Options"));
    }

    #[test]
    fn suggest_fixes_replaces_unsafe_referrer_policy() {
        let mut headers = good_headers();
        headers.insert("referrer-policy", HeaderValue::from_static("unsafe-url"));
        let fixes = suggest_fixes(&headers, &cfg());
        let rp = fixes
            .iter()
            .find(|f| f.header == "Referrer-Policy")
            .expect("expected a Referrer-Policy fix");
        assert_eq!(rp.value, "strict-origin-when-cross-origin");
    }
}
