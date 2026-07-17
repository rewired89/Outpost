use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use outpost::config::{self, CtConfig, EffectiveDomain, HeadersConfig, TlsConfig, TlsVersion};
use outpost::ct::{self, BaselineState};
use outpost::dns;
use outpost::fix;
use outpost::headers;
use outpost::report::{self, DomainReport, Report};
use outpost::tls;

#[derive(Parser)]
#[command(
    name = "outpost",
    version,
    about = "CI security gate for a domain's front-door hygiene: DNSSEC, TLS, Certificate Transparency, and HTTP security headers."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// One-off scan of a single domain using built-in defaults (or a config file's settings for that domain).
    Scan {
        domain: String,
        /// Emit machine-readable JSON instead of a human-readable report.
        #[arg(long)]
        json: bool,
        /// Optional config file to source per-domain overrides from, if the domain is listed in it.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Where CT baseline state is persisted.
        #[arg(long, default_value = "outpost.state.json")]
        state_file: PathBuf,
        #[arg(long)]
        no_dns: bool,
        #[arg(long)]
        no_tls: bool,
        #[arg(long)]
        no_ct: bool,
        #[arg(long)]
        no_headers: bool,
        #[arg(long, value_enum)]
        tls_min_version: Option<CliTlsVersion>,
        #[arg(long)]
        expiry_warning_days: Option<i64>,
    },
    /// Run every domain in a config file as a CI gate. Exits 1 if any check fails.
    Ci {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Find fixable HTTP header issues for a domain and print the exact
    /// change needed for a `_headers` file (Netlify / Cloudflare Pages
    /// format). Read-only: only ever prints a diff, never writes anything.
    /// Never touches DNS, TLS, or CT findings -- there's no safe repo-file
    /// fix for those.
    Fix {
        domain: String,
        #[arg(long)]
        config: Option<PathBuf>,
        /// Local checkout of the repo containing the `_headers` file.
        #[arg(long, default_value = ".")]
        repo_path: PathBuf,
        #[arg(long, default_value = "_headers")]
        headers_file: String,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum CliTlsVersion {
    #[value(name = "1.2")]
    Tls12,
    #[value(name = "1.3")]
    Tls13,
}

impl From<CliTlsVersion> for TlsVersion {
    fn from(v: CliTlsVersion) -> Self {
        match v {
            CliTlsVersion::Tls12 => TlsVersion::Tls12,
            CliTlsVersion::Tls13 => TlsVersion::Tls13,
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan {
            domain,
            json,
            config,
            state_file,
            no_dns,
            no_tls,
            no_ct,
            no_headers,
            tls_min_version,
            expiry_warning_days,
        } => {
            let mut effective = match &config {
                Some(path) => match config::Config::load(path) {
                    Ok(cfg) => cfg
                        .effective_domains()
                        .into_iter()
                        .find(|d| d.name == domain)
                        .unwrap_or_else(|| default_domain(&domain)),
                    Err(e) => {
                        eprintln!("error loading config {}: {e}", path.display());
                        return ExitCode::from(2);
                    }
                },
                None => default_domain(&domain),
            };

            if no_dns {
                effective.checks.dns = false;
            }
            if no_tls {
                effective.checks.tls = false;
            }
            if no_ct {
                effective.checks.ct = false;
            }
            if no_headers {
                effective.checks.headers = false;
            }
            if let Some(v) = tls_min_version {
                effective.tls.min_version = v.into();
            }
            if let Some(d) = expiry_warning_days {
                effective.tls.expiry_warning_days = d;
            }

            let mut state = BaselineState::load(&state_file);
            let domain_report = run_domain(&effective, &mut state).await;
            if let Err(e) = state.save(&state_file) {
                eprintln!(
                    "warning: could not persist CT baseline state to {}: {e}",
                    state_file.display()
                );
            }

            let mut report = Report::new();
            let has_failure = domain_report.has_failure();
            report.push(domain_report);

            print_report(&report, json);
            exit_code(has_failure)
        }

        Command::Ci { config, json } => {
            let cfg = match config::Config::load(&config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error loading config {}: {e}", config.display());
                    return ExitCode::from(2);
                }
            };

            let mut state = BaselineState::load(&cfg.state_file);
            let mut report = Report::new();

            for domain in cfg.effective_domains() {
                let domain_report = run_domain(&domain, &mut state).await;
                report.push(domain_report);
            }

            if let Err(e) = state.save(&cfg.state_file) {
                eprintln!(
                    "warning: could not persist CT baseline state to {}: {e}",
                    cfg.state_file.display()
                );
            }

            let has_failure = report.has_failure();
            print_report(&report, json);
            exit_code(has_failure)
        }

        Command::Fix {
            domain,
            config,
            repo_path,
            headers_file,
        } => {
            let effective = match &config {
                Some(path) => match config::Config::load(path) {
                    Ok(cfg) => cfg
                        .effective_domains()
                        .into_iter()
                        .find(|d| d.name == domain)
                        .unwrap_or_else(|| default_domain(&domain)),
                    Err(e) => {
                        eprintln!("error loading config {}: {e}", path.display());
                        return ExitCode::from(2);
                    }
                },
                None => default_domain(&domain),
            };

            let url = format!("https://{domain}/");
            let client = match reqwest::Client::builder()
                .user_agent(concat!("outpost/", env!("CARGO_PKG_VERSION")))
                .build()
            {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("could not build HTTP client: {e}");
                    return ExitCode::from(2);
                }
            };
            let response = match client.get(&url).send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("could not fetch {url}: {e}");
                    return ExitCode::from(2);
                }
            };

            let fixes = headers::suggest_fixes(response.headers(), &effective.headers);
            if fixes.is_empty() {
                println!("No fixable header issues found for {domain}.");
                return ExitCode::SUCCESS;
            }

            let plan = match fix::plan(&repo_path, &headers_file, &fixes) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!(
                        "could not read {}: {e}",
                        repo_path.join(&headers_file).display()
                    );
                    return ExitCode::from(2);
                }
            };

            if plan.is_noop() {
                println!(
                    "{} already has these headers -- nothing to change.",
                    plan.file_path.display()
                );
                println!(
                    "(The live site at {domain} doesn't have them yet -- this just means an \
                     earlier run already wrote the fix locally. If a pull request is still \
                     open from that run, that's the one to merge.)"
                );
                return ExitCode::SUCCESS;
            }

            println!("Proposed changes to {}:\n", plan.file_path.display());
            for f in &plan.fixes {
                println!("  + {}: {}", f.header, f.value);
                println!("      {}", f.reason);
            }
            println!("\n--- before ---\n{}", plan.before);
            println!("--- after ---\n{}", plan.after);
            println!(
                "\nNo files were changed -- outpost fix only ever prints what to change. \
                 Apply it yourself and commit it however you normally would."
            );
            ExitCode::SUCCESS
        }
    }
}

fn default_domain(name: &str) -> EffectiveDomain {
    EffectiveDomain {
        name: name.to_string(),
        checks: config::ChecksEnabled::default(),
        tls: TlsConfig::default(),
        headers: HeadersConfig::default(),
        ct: CtConfig::default(),
    }
}

async fn run_domain(domain: &EffectiveDomain, state: &mut BaselineState) -> DomainReport {
    let mut report = DomainReport::new(domain.name.clone());

    // The TLS check runs first (when enabled) so the CT check can reuse its
    // live leaf certificate for fingerprint pinning instead of opening a
    // second connection.
    let mut live_leaf_der: Option<Vec<u8>> = None;

    if domain.checks.tls {
        match tls::connect(&domain.name).await {
            Ok(info) => {
                live_leaf_der = info.chain_der.first().cloned();
                report.push(tls::evaluate(&domain.name, &info, &domain.tls));
            }
            Err(e) => report.push(tls::error_to_result(&domain.name, e)),
        }
    } else {
        report.push(report::CheckResult::skip("tls", "disabled by config"));
    }

    if domain.checks.dns {
        report.push(dns::check(&domain.name).await);
    } else {
        report.push(report::CheckResult::skip("dns", "disabled by config"));
    }

    if domain.checks.headers {
        report.push(headers::check(&domain.name, &domain.headers).await);
    } else {
        report.push(report::CheckResult::skip("headers", "disabled by config"));
    }

    if domain.checks.ct {
        report.push(ct::check(&domain.name, &domain.ct, state, live_leaf_der.as_deref()).await);
    } else {
        report.push(report::CheckResult::skip("ct", "disabled by config"));
    }

    report
}

fn print_report(report: &Report, json: bool) {
    if json {
        println!("{}", report.to_json_pretty());
    } else {
        print!("{}", report.to_human());
    }
}

fn exit_code(has_failure: bool) -> ExitCode {
    if has_failure {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
