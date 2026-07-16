//! Library surface for `outpost`, split out from the binary so integration
//! tests (in `tests/`) can exercise each check module directly -- against
//! live, stable public domains and against mocked failure fixtures -- without
//! going through the CLI.

pub mod config;
pub mod ct;
pub mod dns;
pub mod fix;
pub mod headers;
pub mod headers_file;
pub mod report;
pub mod tls;
