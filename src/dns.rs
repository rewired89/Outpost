//! DNSSEC check.
//!
//! Resolves the domain through a locally cryptographically validating
//! resolver (`hickory-resolver` built with the `dnssec-ring` feature) rather
//! than shelling out to `dig +dnssec` or trusting an upstream resolver's `AD`
//! bit. The upstream nameserver (Cloudflare's `1.1.1.1`/`1.0.0.1`) is used
//! only as a transport to fetch the raw DNSKEY/RRSIG/DS records; the actual
//! chain-of-trust validation from the IANA root down to the queried name
//! happens inside this process, using `hickory-resolver`'s built-in root
//! trust anchor.
//!
//! A domain that has never deployed DNSSEC resolves as [`Proof::Insecure`]
//! and is treated as a *failure* here: this tool's whole premise is that the
//! DNS front door should be signed, not merely that it isn't actively under
//! attack today.

use hickory_resolver::{
    config::{ResolverConfig, CLOUDFLARE},
    net::runtime::TokioRuntimeProvider,
    proto::dnssec::Proof,
    Resolver,
};

use crate::report::CheckResult;

const CHECK_NAME: &str = "dns";

fn build_resolver() -> Result<hickory_resolver::Resolver<TokioRuntimeProvider>, anyhow::Error> {
    let mut builder = Resolver::builder_with_config(
        ResolverConfig::udp_and_tcp(&CLOUDFLARE),
        TokioRuntimeProvider::default(),
    );
    builder.options_mut().validate = true;
    builder.options_mut().try_tcp_on_error = true;
    builder
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build resolver: {e}"))
}

pub async fn check(domain: &str) -> CheckResult {
    let resolver = match build_resolver() {
        Ok(r) => r,
        Err(e) => {
            return CheckResult::skip(
                CHECK_NAME,
                format!("could not initialize DNSSEC-validating resolver: {e}"),
            );
        }
    };

    let fqdn = format!("{domain}.");

    // Prefer A/AAAA since that's what a "front door" check cares about; fall
    // back to NS if the apex has no address records (e.g. it's delegated
    // purely for mail or is a bare zone cut).
    let proofs = match resolver.lookup_ip(fqdn.as_str()).await {
        Ok(lookup) => collect_proofs(lookup.as_lookup().answers()),
        Err(ip_err) => match resolver.ns_lookup(fqdn.as_str()).await {
            Ok(lookup) => collect_proofs(lookup.answers()),
            Err(ns_err) => {
                return CheckResult::skip(
                    CHECK_NAME,
                    format!("DNS resolution failed for {domain} (A/AAAA: {ip_err}; NS: {ns_err})"),
                );
            }
        },
    };

    evaluate(domain, &proofs)
}

fn collect_proofs(records: &[hickory_resolver::proto::rr::Record]) -> Vec<Proof> {
    records.iter().map(|r| r.proof).collect()
}

/// Pure evaluation of a set of per-record DNSSEC proofs, split out for unit
/// testing without needing live network access.
fn evaluate(domain: &str, proofs: &[Proof]) -> CheckResult {
    if proofs.is_empty() {
        return CheckResult::skip(
            CHECK_NAME,
            format!("no records returned for {domain}; cannot assess DNSSEC status"),
        );
    }

    if proofs.iter().any(|p| p.is_bogus()) {
        return CheckResult::fail(
            CHECK_NAME,
            format!("DNSSEC validation is BOGUS for {domain}"),
        )
        .with_detail(
            "signatures failed to validate against the chain of trust -- this can indicate a \
             misconfiguration (expired RRSIG, key rollover mismatch) or a spoofing attempt"
                .to_string(),
        );
    }

    if proofs.iter().all(|p| p.is_secure()) {
        return CheckResult::pass(
            CHECK_NAME,
            format!("DNSSEC chain validated (Secure) for {domain}"),
        );
    }

    if proofs.iter().any(|p| p.is_insecure()) {
        return CheckResult::fail(
            CHECK_NAME,
            format!("{domain} is not DNSSEC-signed (Insecure)"),
        )
        .with_detail(
            "no chain of signed DNSKEY/DS records from the root to this zone; DNS answers for \
             this domain are not cryptographically protected against forgery"
                .to_string(),
        );
    }

    CheckResult::skip(
        CHECK_NAME,
        format!("DNSSEC status for {domain} is Indeterminate"),
    )
    .with_detail(
        "resolver could not obtain the DNSSEC records needed to make a determination; retry, or \
         check connectivity to the authoritative nameservers"
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Status;

    #[test]
    fn all_secure_passes() {
        let result = evaluate("example.com", &[Proof::Secure, Proof::Secure]);
        assert_eq!(result.status, Status::Pass);
    }

    #[test]
    fn any_bogus_fails_even_if_others_secure() {
        let result = evaluate("example.com", &[Proof::Secure, Proof::Bogus]);
        assert_eq!(result.status, Status::Fail);
        assert!(result.summary.contains("BOGUS"));
    }

    #[test]
    fn all_insecure_fails_as_unsigned() {
        let result = evaluate("example.com", &[Proof::Insecure, Proof::Insecure]);
        assert_eq!(result.status, Status::Fail);
        assert!(result.summary.contains("not DNSSEC-signed"));
    }

    #[test]
    fn indeterminate_skips_rather_than_fails() {
        let result = evaluate("example.com", &[Proof::Indeterminate]);
        assert_eq!(result.status, Status::Skip);
    }

    #[test]
    fn empty_proofs_skips() {
        let result = evaluate("example.com", &[]);
        assert_eq!(result.status, Status::Skip);
    }
}
