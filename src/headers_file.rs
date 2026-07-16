//! Safe, minimal patcher for the Netlify / Cloudflare Pages `_headers` file
//! format: <https://developers.cloudflare.com/pages/configuration/headers/>
//!
//! Deliberately does not attempt to parse or rewrite nginx/Apache/other
//! server config formats -- those vary too much per site to edit safely
//! without a human reviewing every line by hand. This format's syntax is
//! simple enough (a path pattern line, followed by indented `Header: value`
//! lines) that a targeted patch can add or replace one header without
//! touching anything else in the file.

use crate::headers::HeaderFix;

const SITE_WIDE_PATTERN: &str = "/*";

struct Block {
    pattern: String,
    lines: Vec<String>,
}

/// Apply `fixes` to the site-wide (`/*`) block of an existing `_headers`
/// file's contents, creating that block if the file is empty or doesn't have
/// one yet. Returns the new full file contents. Pure function: no I/O, so
/// it's testable with hand-built input strings.
pub fn apply_fixes(existing: &str, fixes: &[HeaderFix]) -> String {
    if fixes.is_empty() {
        return existing.to_string();
    }

    let mut blocks = parse_blocks(existing);

    let block_index = match blocks.iter().position(|b| b.pattern == SITE_WIDE_PATTERN) {
        Some(i) => i,
        None => {
            blocks.push(Block {
                pattern: SITE_WIDE_PATTERN.to_string(),
                lines: Vec::new(),
            });
            blocks.len() - 1
        }
    };
    let block = &mut blocks[block_index];

    for fix in fixes {
        let new_line = format!("{}: {}", fix.header, fix.value);
        match block
            .lines
            .iter()
            .position(|l| header_name(l).eq_ignore_ascii_case(&fix.header))
        {
            Some(i) => block.lines[i] = new_line,
            None => block.lines.push(new_line),
        }
    }

    render(&blocks)
}

fn header_name(line: &str) -> &str {
    line.split(':').next().unwrap_or("").trim()
}

fn parse_blocks(contents: &str) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut current: Option<Block> = None;

    for raw_line in contents.lines() {
        let line = raw_line.trim_end();
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(char::is_whitespace) {
            if let Some(b) = current.take() {
                blocks.push(b);
            }
            current = Some(Block {
                pattern: line.trim().to_string(),
                lines: Vec::new(),
            });
        } else if let Some(b) = current.as_mut() {
            b.lines.push(line.trim().to_string());
        }
    }
    if let Some(b) = current.take() {
        blocks.push(b);
    }
    blocks
}

fn render(blocks: &[Block]) -> String {
    let mut out = String::new();
    for (i, block) in blocks.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&block.pattern);
        out.push('\n');
        for line in &block.lines {
            out.push_str("  ");
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fix(header: &str, value: &str) -> HeaderFix {
        HeaderFix {
            header: header.to_string(),
            value: value.to_string(),
            reason: "test".to_string(),
        }
    }

    #[test]
    fn creates_site_wide_block_in_empty_file() {
        let result = apply_fixes("", &[fix("X-Frame-Options", "DENY")]);
        assert_eq!(result, "/*\n  X-Frame-Options: DENY\n");
    }

    #[test]
    fn appends_to_existing_site_wide_block() {
        let existing = "/*\n  X-Content-Type-Options: nosniff\n";
        let result = apply_fixes(existing, &[fix("X-Frame-Options", "DENY")]);
        assert_eq!(
            result,
            "/*\n  X-Content-Type-Options: nosniff\n  X-Frame-Options: DENY\n"
        );
    }

    #[test]
    fn replaces_existing_header_value_in_place_case_insensitively() {
        let existing = "/*\n  strict-transport-security: max-age=60\n";
        let result = apply_fixes(
            existing,
            &[fix("Strict-Transport-Security", "max-age=31536000")],
        );
        assert_eq!(
            result,
            "/*\n  Strict-Transport-Security: max-age=31536000\n"
        );
    }

    #[test]
    fn preserves_other_path_blocks_untouched() {
        let existing =
            "/api/*\n  Cache-Control: no-store\n\n/*\n  X-Content-Type-Options: nosniff\n";
        let result = apply_fixes(existing, &[fix("X-Frame-Options", "DENY")]);
        assert!(result.contains("/api/*\n  Cache-Control: no-store\n"));
        assert!(result.contains("X-Frame-Options: DENY"));
    }

    #[test]
    fn no_fixes_leaves_file_byte_for_byte_unchanged() {
        let existing = "/*\n  X-Content-Type-Options: nosniff\n";
        let result = apply_fixes(existing, &[]);
        assert_eq!(result, existing);
    }

    #[test]
    fn multiple_fixes_in_one_pass() {
        let result = apply_fixes(
            "",
            &[
                fix("X-Frame-Options", "DENY"),
                fix("X-Content-Type-Options", "nosniff"),
            ],
        );
        assert_eq!(
            result,
            "/*\n  X-Frame-Options: DENY\n  X-Content-Type-Options: nosniff\n"
        );
    }
}
