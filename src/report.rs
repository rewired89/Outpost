//! Shared result types and rendering (human-readable + JSON) for all checks.

use serde::Serialize;

/// Outcome of a single check against a single domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Check ran and everything matched the expected baseline.
    Pass,
    /// Check ran but found something that should be looked at, without
    /// necessarily being a security failure (e.g. a cert expiring in 10 days).
    Warn,
    /// Check ran and found a security-relevant drift from baseline; this
    /// fails the build.
    Fail,
    /// Check could not be completed (network error, timeout, disabled
    /// upstream, etc). Does not fail the build by itself, but is surfaced
    /// distinctly from `Pass` so it isn't mistaken for a clean bill of health.
    Skip,
}

impl Status {
    pub fn is_failing(self) -> bool {
        matches!(self, Status::Fail)
    }

    fn icon(self) -> &'static str {
        match self {
            Status::Pass => "\u{2713}", // check mark
            Status::Warn => "!",
            Status::Fail => "\u{2717}", // cross mark
            Status::Skip => "-",
        }
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Status::Pass => write!(f, "PASS"),
            Status::Warn => write!(f, "WARN"),
            Status::Fail => write!(f, "FAIL"),
            Status::Skip => write!(f, "SKIP"),
        }
    }
}

/// Result of one named check (dns / tls / ct / headers) for one domain.
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub check: String,
    pub status: Status,
    pub summary: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<String>,
}

impl CheckResult {
    pub fn pass(check: &str, summary: impl Into<String>) -> Self {
        Self {
            check: check.to_string(),
            status: Status::Pass,
            summary: summary.into(),
            details: Vec::new(),
        }
    }

    pub fn warn(check: &str, summary: impl Into<String>) -> Self {
        Self {
            check: check.to_string(),
            status: Status::Warn,
            summary: summary.into(),
            details: Vec::new(),
        }
    }

    pub fn fail(check: &str, summary: impl Into<String>) -> Self {
        Self {
            check: check.to_string(),
            status: Status::Fail,
            summary: summary.into(),
            details: Vec::new(),
        }
    }

    pub fn skip(check: &str, summary: impl Into<String>) -> Self {
        Self {
            check: check.to_string(),
            status: Status::Skip,
            summary: summary.into(),
            details: Vec::new(),
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.details.push(detail.into());
        self
    }

    pub fn with_details(mut self, details: Vec<String>) -> Self {
        self.details.extend(details);
        self
    }
}

/// All check results for a single domain.
#[derive(Debug, Clone, Serialize)]
pub struct DomainReport {
    pub domain: String,
    pub results: Vec<CheckResult>,
}

impl DomainReport {
    pub fn new(domain: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            results: Vec::new(),
        }
    }

    pub fn push(&mut self, result: CheckResult) {
        self.results.push(result);
    }

    pub fn has_failure(&self) -> bool {
        self.results.iter().any(|r| r.status.is_failing())
    }

    pub fn worst_status(&self) -> Status {
        self.results
            .iter()
            .map(|r| r.status)
            .max_by_key(|s| match s {
                Status::Fail => 3,
                Status::Warn => 2,
                Status::Skip => 1,
                Status::Pass => 0,
            })
            .unwrap_or(Status::Skip)
    }
}

/// The complete result of a run across every scanned domain.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub domains: Vec<DomainReport>,
}

impl Report {
    pub fn new() -> Self {
        Self {
            domains: Vec::new(),
        }
    }

    pub fn push(&mut self, domain: DomainReport) {
        self.domains.push(domain);
    }

    /// True if any domain has a failing check -- callers should exit(1).
    pub fn has_failure(&self) -> bool {
        self.domains.iter().any(|d| d.has_failure())
    }

    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Render a human-readable report to a String.
    pub fn to_human(&self) -> String {
        let mut out = String::new();
        for domain in &self.domains {
            out.push_str(&format!(
                "== {} [{}] ==\n",
                domain.domain,
                domain.worst_status()
            ));
            for result in &domain.results {
                out.push_str(&format!(
                    "  [{}] {:<8} {}: {}\n",
                    result.status.icon(),
                    result.status.to_string(),
                    result.check,
                    result.summary
                ));
                for detail in &result.details {
                    out.push_str(&format!("        - {detail}\n"));
                }
            }
            out.push('\n');
        }

        let total_fail: usize = self
            .domains
            .iter()
            .map(|d| {
                d.results
                    .iter()
                    .filter(|r| r.status == Status::Fail)
                    .count()
            })
            .sum();
        let total_warn: usize = self
            .domains
            .iter()
            .map(|d| {
                d.results
                    .iter()
                    .filter(|r| r.status == Status::Warn)
                    .count()
            })
            .sum();
        let total_skip: usize = self
            .domains
            .iter()
            .map(|d| {
                d.results
                    .iter()
                    .filter(|r| r.status == Status::Skip)
                    .count()
            })
            .sum();

        if total_fail > 0 {
            out.push_str(&format!(
                "RESULT: FAIL ({total_fail} failing, {total_warn} warnings, {total_skip} skipped)\n"
            ));
        } else {
            out.push_str(&format!(
                "RESULT: PASS ({total_warn} warnings, {total_skip} skipped)\n"
            ));
        }
        out
    }
}

impl Default for Report {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worst_status_prioritizes_fail_over_warn_and_skip() {
        let mut domain = DomainReport::new("example.com");
        domain.push(CheckResult::pass("headers", "ok"));
        domain.push(CheckResult::warn("tls", "expiring soon"));
        domain.push(CheckResult::skip("ct", "network unavailable"));
        assert_eq!(domain.worst_status(), Status::Warn);

        domain.push(CheckResult::fail("dns", "bogus signature"));
        assert_eq!(domain.worst_status(), Status::Fail);
        assert!(domain.has_failure());
    }

    #[test]
    fn report_has_failure_aggregates_across_domains() {
        let mut report = Report::new();
        let mut clean = DomainReport::new("clean.example.com");
        clean.push(CheckResult::pass("headers", "ok"));
        report.push(clean);

        let mut broken = DomainReport::new("broken.example.com");
        broken.push(CheckResult::fail("tls", "expired certificate"));
        report.push(broken);

        assert!(report.has_failure());
    }

    #[test]
    fn json_output_is_valid_json() {
        let mut report = Report::new();
        let mut domain = DomainReport::new("example.com");
        domain.push(CheckResult::pass("headers", "all required headers present"));
        report.push(domain);
        let json = report.to_json_pretty();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["domains"][0]["domain"], "example.com");
        assert_eq!(parsed["domains"][0]["results"][0]["status"], "pass");
    }
}
