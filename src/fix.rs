//! Propose a fix for fixable header findings as a pull request, rather than
//! applying it directly.
//!
//! Outpost only ever *observes* a domain from outside -- it has no write
//! access to the server, DNS, or certificate authority that would be needed
//! to fix a DNSSEC, TLS, or Certificate Transparency finding, and it should
//! never be given that access: a checker with the power to change what it's
//! checking stops being a trustworthy, independent auditor. Headers are
//! different only because, for a large and growing share of sites (anything
//! on Netlify or Cloudflare Pages), the fix is a one-line addition to a
//! plain-text `_headers` file already sitting in the site's own repo -- so
//! it can be proposed as an ordinary, human-reviewed pull request instead.
//!
//! `plan()` is pure and safe to call any time: it reads the existing file
//! (if any) and computes what the new contents would be. `apply_and_open_pr`
//! is the only function in this module that writes anything or talks to the
//! network, and the CLI only calls it when the user passed `--yes`.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::headers::HeaderFix;
use crate::headers_file;

#[derive(Debug, thiserror::Error)]
pub enum FixError {
    #[error("git command failed: {0}")]
    Git(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("GitHub API error: {0}")]
    GitHub(String),
}

/// What would change, computed without touching git or the network.
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

pub struct GitHubTarget {
    pub owner: String,
    pub repo: String,
    pub base_branch: String,
    pub token: String,
}

/// Write the planned file, commit it to a new branch, push, and open a pull
/// request against `target`. Never merges anything -- a human has to do
/// that. Returns the PR's URL.
pub async fn apply_and_open_pr(
    repo_path: &Path,
    plan: &FixPlan,
    domain: &str,
    target: &GitHubTarget,
) -> Result<String, FixError> {
    std::fs::write(&plan.file_path, &plan.after)?;

    let relative_path = plan
        .file_path
        .strip_prefix(repo_path)
        .unwrap_or(&plan.file_path);
    let branch = format!("outpost/fix-headers-{}", domain.replace('.', "-"));

    // `-B` (not `-b`) resets the branch to the current HEAD if it already
    // exists, instead of erroring -- this branch name is deterministic per
    // domain, so a retry after any earlier failure (bad token, network
    // blip, whatever) should just redo it, not get stuck forever. Same
    // reasoning for `--force` on the push: only Outpost ever writes to its
    // own `outpost/fix-headers-*` branches, so overwriting a stale one from
    // a failed prior attempt is exactly what a retry should do -- this is
    // not a branch a human is expected to have based other work on.
    run_git(repo_path, &["checkout", "-B", &branch])?;
    run_git(repo_path, &["add", &relative_path.to_string_lossy()])?;
    run_git(
        repo_path,
        &[
            "commit",
            "-m",
            &format!("outpost: fix security headers for {domain}"),
        ],
    )?;
    run_git(repo_path, &["push", "-u", "origin", &branch, "--force"])?;

    let client = reqwest::Client::builder()
        .user_agent(concat!("outpost/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| FixError::GitHub(e.to_string()))?;

    let body = serde_json::json!({
        "title": format!("outpost: fix security headers for {domain}"),
        "head": branch,
        "base": target.base_branch,
        "body": pr_body(domain, &plan.fixes),
    });

    let response = client
        .post(format!(
            "https://api.github.com/repos/{}/{}/pulls",
            target.owner, target.repo
        ))
        .bearer_auth(&target.token)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", concat!("outpost/", env!("CARGO_PKG_VERSION")))
        .json(&body)
        .send()
        .await
        .map_err(|e| FixError::GitHub(e.to_string()))?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(FixError::GitHub(format!(
            "GitHub returned {status}: {text}"
        )));
    }

    let json: serde_json::Value = response
        .json()
        .await
        .map_err(|e| FixError::GitHub(e.to_string()))?;

    json.get("html_url")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| FixError::GitHub("response missing html_url".to_string()))
}

fn pr_body(domain: &str, fixes: &[HeaderFix]) -> String {
    let mut body = format!(
        "Outpost's header check found {} missing or weak security header(s) on `{domain}`.\n\n\
         This adds them to `_headers`. Nothing was applied to the live site automatically --\n\
         review the diff and merge it yourself if it looks right.\n\n\
         | Header | Value | Why |\n|---|---|---|\n",
        fixes.len()
    );
    for f in fixes {
        body.push_str(&format!(
            "| `{}` | `{}` | {} |\n",
            f.header, f.value, f.reason
        ));
    }
    body
}

fn run_git(repo_path: &Path, args: &[&str]) -> Result<(), FixError> {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo_path)
        .output()?;
    if !output.status.success() {
        // git puts some failure explanations (e.g. "nothing to commit") on
        // stdout rather than stderr -- show both, or a real error can come
        // back looking blank, which is worse than no error message at all.
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let detail = match (stderr.trim().is_empty(), stdout.trim().is_empty()) {
            (false, _) => stderr.trim().to_string(),
            (true, false) => stdout.trim().to_string(),
            (true, true) => format!("exit status {}", output.status),
        };
        return Err(FixError::Git(format!("git {}: {}", args.join(" "), detail)));
    }
    Ok(())
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
        // The exact scenario a real run hit: a prior attempt already wrote
        // the fixed _headers file to disk before failing later on (a
        // network error, a bad token, whatever). suggest_fixes() still
        // returns the same fixes on retry (it's computed from the live
        // site, not the local file), but applying them to a file that
        // already has them produces byte-identical output -- plan() must
        // recognize that as a no-op so the CLI doesn't try to commit
        // nothing and get a confusing git failure.
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

    #[test]
    fn local_git_flow_writes_branch_and_commit_without_touching_github() {
        // apply_and_open_pr itself isn't called here -- it ends in a real
        // network call to GitHub's API, which needs a real token and isn't
        // appropriate for this test tier. This exercises the same local git
        // mechanics (write, branch, add, commit) that function performs
        // before it ever reaches the network, against a real throwaway repo.
        let dir = tempfile::tempdir().unwrap();
        let repo_path = dir.path();

        let init = Command::new("git")
            .args(["init"])
            .current_dir(repo_path)
            .output()
            .unwrap();
        assert!(init.status.success());
        Command::new("git")
            .args(["config", "user.email", "test@example.com"])
            .current_dir(repo_path)
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(repo_path)
            .output()
            .unwrap();
        std::fs::write(repo_path.join("README.md"), "test repo\n").unwrap();
        Command::new("git")
            .args(["add", "README.md"])
            .current_dir(repo_path)
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(repo_path)
            .output()
            .unwrap();

        let fixes = vec![fix("X-Frame-Options", "DENY")];
        let plan = plan(repo_path, "_headers", &fixes).unwrap();

        std::fs::write(&plan.file_path, &plan.after).unwrap();
        run_git(repo_path, &["checkout", "-b", "outpost/fix-headers-test"]).unwrap();
        run_git(repo_path, &["add", "_headers"]).unwrap();
        run_git(
            repo_path,
            &["commit", "-m", "outpost: fix security headers for test"],
        )
        .unwrap();

        let log = Command::new("git")
            .args(["log", "--oneline", "-1"])
            .current_dir(repo_path)
            .output()
            .unwrap();
        let log_text = String::from_utf8_lossy(&log.stdout);
        assert!(log_text.contains("outpost: fix security headers"));

        let written = std::fs::read_to_string(repo_path.join("_headers")).unwrap();
        assert!(written.contains("X-Frame-Options: DENY"));
    }
}
