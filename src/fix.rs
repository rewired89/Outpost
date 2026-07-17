//! Compute the exact fix for fixable header findings, without writing
//! anything.
//!
//! Outpost only ever *observes* a domain from outside -- it has no write
//! access to the server, DNS, or certificate authority that would be needed
//! to fix a DNSSEC, TLS, or Certificate Transparency finding, and it should
//! never be given that access: a checker with the power to change what it's
//! checking stops being a trustworthy, independent auditor. Headers are the
//! one finding with a config file (the Netlify / Cloudflare Pages
//! `_headers` format) simple enough to compute an exact patch for -- but
//! `outpost fix` only ever prints that patch. It never writes the file,
//! never touches git, and never calls any network API. Applying the change
//! is entirely up to the person running it.

use std::path::{Path, PathBuf};

use crate::headers::HeaderFix;
use crate::headers_file;

/// What would change, computed without touching disk or the network beyond
/// the one read of the existing `_headers` file (if any).
pub struct FixPlan {
    pub file_path: PathBuf,
    pub before: String,
    pub after: String,
    pub fixes: Vec<HeaderFix>,
}

impl FixPlan {
    pub fn is_noop(&self) -> bool {
        self.before == self.after
    }
}

/// Read `repo_path/headers_file` (treating a missing file as empty) and
/// compute the patched contents. Never writes anything.
pub fn plan(repo_path: &Path, headers_file: &str, fixes: &[HeaderFix]) -> std::io::Result<FixPlan> {
    let file_path = repo_path.join(headers_file);
    let before = match std::fs::read_to_string(&file_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    let after = headers_file::apply_fixes(&before, fixes);
    Ok(FixPlan {
        file_path,
        before,
        after,
        fixes: fixes.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headers::HeaderFix;

    fn fix(header: &str, value: &str) -> HeaderFix {
        HeaderFix {
            header: header.to_string(),
            value: value.to_string(),
            reason: "test".to_string(),
        }
    }

    #[test]
    fn plan_treats_missing_file_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let plan = plan(dir.path(), "_headers", &[fix("X-Frame-Options", "DENY")]).unwrap();
        assert_eq!(plan.before, "");
        assert!(plan.after.contains("X-Frame-Options: DENY"));
        assert!(!plan.is_noop());
    }

    #[test]
    fn plan_reads_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("_headers"),
            "/*\n  X-Content-Type-Options: nosniff\n",
        )
        .unwrap();
        let plan = plan(dir.path(), "_headers", &[fix("X-Frame-Options", "DENY")]).unwrap();
        assert!(plan.before.contains("X-Content-Type-Options"));
        assert!(plan.after.contains("X-Content-Type-Options"));
        assert!(plan.after.contains("X-Frame-Options: DENY"));
    }

    #[test]
    fn plan_is_a_noop_when_the_file_already_has_the_suggested_fixes() {
        // suggest_fixes() is computed from the live site, not the local
        // file, so re-running against a file someone already hand-applied
        // the fix to should report nothing left to do, not an empty diff
        // that looks like a bug.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("_headers"), "/*\n  X-Frame-Options: DENY\n").unwrap();
        let plan = plan(dir.path(), "_headers", &[fix("X-Frame-Options", "DENY")]).unwrap();
        assert!(!plan.fixes.is_empty());
        assert!(plan.is_noop());
    }

    #[test]
    fn plan_with_no_fixes_is_a_noop() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("_headers"),
            "/*\n  X-Content-Type-Options: nosniff\n",
        )
        .unwrap();
        let plan = plan(dir.path(), "_headers", &[]).unwrap();
        assert!(plan.is_noop());
    }
}
