//! Membrane daemon entry point.
//!
//! v1 surface (this binary):
//!   membrane-daemon run                       — start the daemon (default)
//!   membrane-daemon status                    — show config and policy
//!   membrane-daemon mode <mode> ...           — change policy mode
//!   membrane-daemon audit [--since=...]       — read the audit log
//!   membrane-daemon pair --token <T>          — install a pairing token
//!   membrane-daemon pair --csr [--out PATH]   — print/save a CSR
//!
//! All real logic lives in `membrane_daemon` (the lib crate); this
//! binary is just CLI dispatch.

use clap::{Parser, Subcommand};

use membrane_daemon::{audit, config, paths, rpc, tunnel, pairing, service};
use config::{Config, PolicyMode};

#[derive(Parser)]
#[command(name = "membrane-daemon")]
#[command(about = "Customer-side daemon for membrane cloud", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Start the daemon and connect to the cloud (default).
    Run,

    /// Serve over stdio instead of QUIC (development / testing).
    #[command(hide = true)]
    RunStdio,

    /// Show current configuration and policy.
    Status,

    /// Change policy mode.
    Mode {
        /// Mode: unrestricted | workspace | allowlist | readonly
        mode: String,
        /// Workspace root (repeatable). Required for workspace/allowlist/readonly modes.
        #[arg(long = "root")]
        roots: Vec<std::path::PathBuf>,
        /// Allowed binary (repeatable). Required for allowlist mode.
        #[arg(long = "allow-bin")]
        allow_bins: Vec<String>,
    },

    /// Read the audit log.
    Audit {
        /// Show entries since this ISO timestamp (default: 24 hours ago).
        #[arg(long)]
        since: Option<String>,
        /// Limit entries shown.
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },

    /// Pair the daemon with the cloud.
    ///
    /// Three forms:
    ///   - No args: print this daemon's CSR to stdout (manual flow).
    ///   - `--token <T>`: install a previously-obtained pairing token.
    ///   - `--enrol <URL> --api-key <KEY>`: generate a CSR, POST it to
    ///     the cloud's `/v1/agent/enroll` endpoint, and install the
    ///     returned token in one go.
    Pair {
        /// Install this pairing token (base64). Mutually exclusive with --enrol.
        #[arg(long)]
        token: Option<String>,
        /// When generating the CSR, write it to this path instead of stdout.
        #[arg(long)]
        out: Option<std::path::PathBuf>,
        /// Cloud base URL (e.g. https://mcp.membrane.informationpatterns.com).
        /// When set, POST a CSR to {url}/v1/agent/enroll and install the token.
        #[arg(long)]
        enrol: Option<String>,
        /// API key to authenticate the enrol request. Required with --enrol.
        #[arg(long)]
        api_key: Option<String>,
    },

    /// Install the daemon as an OS service (systemd / launchd / Windows).
    Install {
        /// Path to the daemon executable. Defaults to the current binary.
        #[arg(long)]
        exe: Option<std::path::PathBuf>,
    },

    /// Uninstall the OS service.
    Uninstall,

    /// Start the OS service.
    Start,

    /// Stop the OS service.
    Stop,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let cfg = Config::load()?;
    match cli.command.unwrap_or(Command::Run) {
        Command::Run => cmd_run(cfg),
        Command::RunStdio => cmd_run_stdio(cfg),
        Command::Status => cmd_status(cfg),
        Command::Mode { mode, roots, allow_bins } => cmd_mode(cfg, &mode, roots, allow_bins),
        Command::Audit { since, limit } => cmd_audit(cfg, since.as_deref(), limit),
        Command::Pair { token, out, enrol, api_key } => cmd_pair(cfg, token, out, enrol, api_key),
        Command::Install { exe } => cmd_install(exe),
        Command::Uninstall => cmd_uninstall(),
        Command::Start => cmd_start(),
        Command::Stop => cmd_stop(),
    }
}

// ── service-management commands ────────────────────────────────────

fn cmd_install(exe: Option<std::path::PathBuf>) -> anyhow::Result<()> {
    let exe = exe.map(Ok)
        .unwrap_or_else(std::env::current_exe)
        .context("locate daemon executable")?;
    eprintln!("installing service using executable: {}", exe.display());
    service::install(&exe)?;
    let status = service::status().unwrap_or(service::ServiceStatus::Unknown("?".into()));
    eprintln!("status: {status}");
    Ok(())
}

fn cmd_uninstall() -> anyhow::Result<()> {
    service::uninstall()?;
    Ok(())
}

fn cmd_start() -> anyhow::Result<()> {
    service::start()?;
    eprintln!("started");
    Ok(())
}

fn cmd_stop() -> anyhow::Result<()> {
    service::stop()?;
    eprintln!("stopped");
    Ok(())
}

fn cmd_run(cfg: Config) -> anyhow::Result<()> {
    // Initialize tracing — emits to stderr, level controlled by
    // RUST_LOG (default: info for membrane_daemon, warn for deps).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "membrane_daemon=info,warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    // Install ring as the default crypto provider for rustls.
    rustls::crypto::ring::default_provider().install_default().ok();

    let audit = audit::Audit::new(cfg.policy.name());
    audit.write(audit::Event::Lifecycle {
        event: "startup".into(),
        detail: format!("daemon v{} mode={} endpoint={}",
            env!("CARGO_PKG_VERSION"), cfg.policy.name(), cfg.endpoint),
    })?;
    eprintln!("membrane-daemon v{} starting", env!("CARGO_PKG_VERSION"));
    eprintln!("  endpoint: {}", cfg.endpoint);
    eprintln!("  policy:   {}", cfg.policy.name());
    if let Some(roots) = cfg.policy.roots() {
        for r in roots { eprintln!("    root: {}", r.display()); }
    }

    // Run the tunnel forever (reconnects internally).
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(tunnel::run(cfg, audit.clone()));
    audit.write(audit::Event::Lifecycle {
        event: "shutdown".into(),
        detail: match &result {
            Ok(_) => "clean".into(),
            Err(e) => format!("error: {e}"),
        },
    })?;
    result
}

/// Stdio mode — for local testing without QUIC. Hidden CLI command.
fn cmd_run_stdio(cfg: Config) -> anyhow::Result<()> {
    let audit = audit::Audit::new(cfg.policy.name());
    audit.write(audit::Event::Lifecycle {
        event: "startup".into(),
        detail: "stdio mode".into(),
    })?;
    eprintln!("membrane-daemon v{} serving on stdio", env!("CARGO_PKG_VERSION"));
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let result = rpc::serve(stdin.lock(), stdout.lock(), &cfg, &audit);
    audit.write(audit::Event::Lifecycle {
        event: "shutdown".into(),
        detail: match &result { Ok(_) => "clean".into(), Err(e) => e.to_string() },
    })?;
    result.map_err(anyhow::Error::from)
}

fn cmd_status(cfg: Config) -> anyhow::Result<()> {
    println!("Configuration:");
    println!("  endpoint:           {}", cfg.endpoint);
    println!("  policy mode:        {}", cfg.policy.name());
    if let Some(roots) = cfg.policy.roots() {
        println!("  workspace roots:");
        for r in roots { println!("    - {}", r.display()); }
    }
    if let PolicyMode::WorkspaceAllowlistExec { exec_allowlist, .. } = &cfg.policy {
        println!("  exec allowlist:");
        for a in exec_allowlist { println!("    - {}", a); }
    }
    println!("  max exec timeout:   {} ms", cfg.max_exec_timeout_ms);
    println!("  max output:         {} bytes", cfg.max_output_bytes);
    println!("  max single read:    {} bytes", cfg.max_read_bytes);
    println!();
    println!("Paths:");
    println!("  user dir:           {}", paths::user_dir().display());
    println!("  user policy:        {}", paths::user_policy().display());
    println!("  system policy:      {}", paths::system_policy().display());
    println!("  cert:               {}", paths::cert_path().display());
    println!("  audit dir:          {}", paths::audit_dir().display());
    let cert_status = if paths::readable(&paths::cert_path()) { "present" } else { "missing (run `pair`)" };
    println!("  cert status:        {}", cert_status);
    let svc = service::status().unwrap_or(service::ServiceStatus::Unknown("?".into()));
    println!("  service status:     {}", svc);
    Ok(())
}

fn cmd_mode(
    mut cfg: Config,
    mode: &str,
    roots: Vec<std::path::PathBuf>,
    allow_bins: Vec<String>,
) -> anyhow::Result<()> {
    let new_policy = match mode.to_lowercase().as_str() {
        "unrestricted" => PolicyMode::Unrestricted,
        "workspace" => {
            if roots.is_empty() {
                anyhow::bail!("workspace mode requires at least one --root");
            }
            PolicyMode::Workspace { roots }
        }
        "allowlist" | "workspaceallowlistexec" => {
            if roots.is_empty() {
                anyhow::bail!("allowlist mode requires at least one --root");
            }
            if allow_bins.is_empty() {
                anyhow::bail!("allowlist mode requires at least one --allow-bin");
            }
            PolicyMode::WorkspaceAllowlistExec { roots, exec_allowlist: allow_bins }
        }
        "readonly" => {
            if roots.is_empty() {
                anyhow::bail!("readonly mode requires at least one --root");
            }
            PolicyMode::ReadOnly { roots }
        }
        other => anyhow::bail!("unknown mode '{other}'; use: unrestricted, workspace, allowlist, readonly"),
    };
    cfg.policy = new_policy;
    cfg.save_user()?;
    println!("Policy updated to {}.", cfg.policy.name());
    println!("(daemon must be restarted for new policy to take effect)");
    Ok(())
}

fn cmd_audit(_cfg: Config, since: Option<&str>, limit: usize) -> anyhow::Result<()> {
    let dir = paths::audit_dir();
    if !dir.exists() {
        println!("(no audit log yet — daemon hasn't started)");
        return Ok(());
    }
    let since_ts = since
        .map(|s| chrono::DateTime::parse_from_rfc3339(s)
            .map(|t| t.with_timezone(&chrono::Utc))
            .map_err(|e| anyhow::anyhow!("invalid --since: {e}")))
        .transpose()?
        .unwrap_or_else(|| chrono::Utc::now() - chrono::Duration::hours(24));

    let mut entries: Vec<audit::Entry> = Vec::new();
    let mut log_files: Vec<_> = std::fs::read_dir(&dir)?
        .flatten().map(|e| e.path()).collect();
    log_files.sort();
    for f in log_files {
        let Ok(text) = std::fs::read_to_string(&f) else { continue };
        for line in text.lines() {
            let Ok(e): Result<audit::Entry, _> = serde_json::from_str(line) else { continue };
            if e.ts < since_ts { continue; }
            entries.push(e);
        }
    }
    let n = entries.len();
    for e in entries.into_iter().rev().take(limit).rev() {
        // Compact single-line display.
        println!("{}  [{}]  {}",
            e.ts.format("%Y-%m-%d %H:%M:%S"),
            e.mode,
            serde_json::to_string(&e.event).unwrap_or_default());
    }
    if n > limit {
        eprintln!("({} entries shown of {} total; use --limit to widen)", limit.min(n), n);
    } else {
        eprintln!("({} entries)", n);
    }
    Ok(())
}

/// `pair --enrol <URL> --api-key <KEY>` — generate (or reuse) a CSR,
/// POST it to the cloud's `/v1/agent/enroll` endpoint, install the
/// returned token.
///
/// This collapses the three-step manual flow (generate CSR → send to
/// operator → install token) into one operation, suitable for
/// self-serve onboarding where the customer already has an API key.

/// Normalise a cloud URL by stripping trailing slashes and any
/// known cloud-side paths that users sometimes paste by mistake.
/// We accept whatever URL the user gave and always end up with a
/// bare scheme://host[:port] base.
fn normalise_cloud_url(input: &str) -> String {
    let mut s = input.trim().trim_end_matches('/').to_string();
    // Iteratively strip the most common wrong-paste suffixes. A
    // single loop pass handles compounding (e.g. `/v1/mcp/` →
    // `/v1/mcp` → trimmed → `/v1` → trimmed). Bounded so a
    // pathological input can't loop forever.
    let strip_suffixes = [
        "/v1/mcp",
        "/v1/agent/enroll",
        "/v1/agent",
        "/v1",
        "/account/agents",
        "/account/signup",
        "/account/login",
        "/account",
        "/admin/tenants",
        "/admin",
        "/docs",
    ];
    for _ in 0..6 {
        let before = s.len();
        for suffix in &strip_suffixes {
            if s.ends_with(suffix) {
                s.truncate(s.len() - suffix.len());
                s = s.trim_end_matches('/').to_string();
                break;
            }
        }
        if s.len() == before { break; }
    }
    s
}

#[cfg(test)]
mod normalise_tests {
    use super::normalise_cloud_url;

    #[test]
    fn bare_base_url_unchanged() {
        assert_eq!(normalise_cloud_url("https://mcp.example.com"), "https://mcp.example.com");
    }

    #[test]
    fn strips_trailing_slash() {
        assert_eq!(normalise_cloud_url("https://mcp.example.com/"), "https://mcp.example.com");
    }

    #[test]
    fn strips_mcp_path() {
        // The bug Marcus hit: pasted the MCP URL instead of the base.
        assert_eq!(
            normalise_cloud_url("https://mcp.example.com/v1/mcp"),
            "https://mcp.example.com"
        );
    }

    #[test]
    fn strips_account_paths() {
        assert_eq!(
            normalise_cloud_url("https://mcp.example.com/account/agents"),
            "https://mcp.example.com"
        );
    }

    #[test]
    fn handles_whitespace_and_trailing_slash() {
        assert_eq!(
            normalise_cloud_url("  https://mcp.example.com/v1/mcp/  "),
            "https://mcp.example.com"
        );
    }
}

fn cmd_pair_enrol(
    cfg: Config,
    cloud_url: &str,
    api_key: &str,
    key_path: &std::path::Path,
    cert_path: &std::path::Path,
    pin_path: &std::path::Path,
) -> anyhow::Result<()> {
    use anyhow::Context;

    // 1. CSR (generate keypair if needed).
    let (kp, was_new) = pairing::ensure_keypair(key_path)?;
    if was_new {
        eprintln!("generated new daemon keypair at {}", key_path.display());
    } else {
        eprintln!("reusing existing daemon keypair at {}", key_path.display());
    }
    let csr_pem = pairing::build_csr(&kp)?;

    // 2. POST to cloud.
    // Be tolerant of common URL-paste mistakes: people pasting the
    // MCP endpoint URL (e.g. `.../v1/mcp`) instead of the cloud's
    // base URL. Strip known cloud-side paths so we always hit
    // `/v1/agent/enroll`.
    let base = normalise_cloud_url(cloud_url);
    if base != cloud_url.trim_end_matches('/') {
        eprintln!("note: stripped trailing path from --enrol; using base URL {base}");
    }
    let url = format!("{base}/v1/agent/enroll");
    eprintln!("enrolling against {url}");

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("build HTTP client")?;
    let resp = client.post(&url)
        .header("Authorization", format!("Bearer {api_key}"))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({ "csr_pem": csr_pem }))
        .send()
        .with_context(|| format!("POST {url}"))?;
    let status = resp.status();
    // Capture the raw body so we can give a useful error if the
    // server didn't return JSON — far more useful than the bare
    // "EOF while parsing a value" message.
    let body_bytes = resp.bytes()
        .with_context(|| format!("read response body from {url}"))?;
    let body: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => {
            let preview = String::from_utf8_lossy(&body_bytes);
            let preview = preview.chars().take(200).collect::<String>();
            anyhow::bail!(
                "enrolment endpoint returned non-JSON response (status {status})\n\
                 \n\
                 This usually means the --enrol URL is wrong. Make sure you're\n\
                 passing the cloud's base URL (e.g. https://mcp.example.com),\n\
                 not the MCP endpoint (e.g. https://mcp.example.com/v1/mcp).\n\
                 \n\
                 Server returned: {preview}\n\
                 Parse error: {e}"
            );
        }
    };

    if !status.is_success() {
        let err = body.get("error").and_then(|v| v.as_str()).unwrap_or("(unknown error)");
        anyhow::bail!("enrolment rejected ({status}): {err}");
    }
    let token_b64 = body.get("token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("response missing `token` field: {body}"))?;
    let cert_handle = body.get("cert_handle")
        .and_then(|v| v.as_str())
        .unwrap_or("(unknown)");
    eprintln!("cloud issued cert {cert_handle}");

    // 3. Install token (same code path as `pair --token`).
    let parsed = pairing::PairingToken::decode(token_b64.trim())?;
    let prev_endpoint = pairing::install_token(&parsed, &cfg, cert_path, pin_path)?;

    eprintln!();
    eprintln!("paired:");
    eprintln!("  daemon cert: {}", cert_path.display());
    eprintln!("  cloud pin:   {}", pin_path.display());
    eprintln!("  endpoint:    {}", parsed.endpoint);
    if let Some(prev) = prev_endpoint {
        eprintln!("  (previous endpoint was: {prev})");
    }
    let audit = audit::Audit::new(cfg.policy.name());
    audit.write(audit::Event::Lifecycle {
        event: "paired_via_enrol".into(),
        detail: format!("endpoint={} cert={}", parsed.endpoint, cert_handle),
    })?;
    eprintln!();
    eprintln!("Restart the daemon to begin using the new credentials.");
    Ok(())
}

fn cmd_pair(
    cfg: Config,
    token: Option<String>,
    out: Option<std::path::PathBuf>,
    enrol: Option<String>,
    api_key: Option<String>,
) -> anyhow::Result<()>
{
    let key_path = paths::key_path();
    let cert_path = paths::cert_path();
    let pin_path = paths::cloud_pin_path();

    // Validate mutual exclusivity.
    if token.is_some() && enrol.is_some() {
        anyhow::bail!("--token and --enrol are mutually exclusive");
    }
    if enrol.is_some() && api_key.is_none() {
        anyhow::bail!("--enrol requires --api-key");
    }

    // Mode 3: enrol against a cloud directly.
    if let Some(cloud_url) = enrol {
        let api_key = api_key.unwrap();
        return cmd_pair_enrol(cfg, &cloud_url, &api_key,
            &key_path, &cert_path, &pin_path);
    }

    match token {
        // No token → produce a CSR for the operator.
        None => {
            let (kp, was_new) = pairing::ensure_keypair(&key_path)?;
            if was_new {
                eprintln!("generated new daemon keypair at {}", key_path.display());
            } else {
                eprintln!("reusing existing daemon keypair at {}", key_path.display());
            }
            let csr_pem = pairing::build_csr(&kp)?;
            match out {
                Some(p) => {
                    std::fs::write(&p, &csr_pem)?;
                    eprintln!("wrote CSR to {}", p.display());
                }
                None => {
                    print!("{csr_pem}");
                }
            }
            eprintln!();
            eprintln!("Next: send the CSR to the operator.");
            eprintln!("They will return a pairing token. Run:");
            eprintln!("  membrane-daemon pair --token <TOKEN>");
            eprintln!();
            eprintln!("Or skip the manual relay: use --enrol with an API key to");
            eprintln!("POST the CSR to the cloud and install the token in one go:");
            eprintln!("  membrane-daemon pair --enrol <URL> --api-key <KEY>");
            Ok(())
        }

        // Token supplied → install it.
        Some(t) => {
            // Token may be passed inline or as `@path/to/file`.
            let token_str = if let Some(rest) = t.strip_prefix('@') {
                std::fs::read_to_string(rest)
                    .with_context(|| format!("read token file {rest}"))?
            } else { t };

            // Ensure the key exists; the CSR step should have created it.
            if !key_path.exists() {
                anyhow::bail!(
                    "no daemon keypair at {} — run `membrane-daemon pair` (no args) first \
                     to generate one and produce a CSR",
                    key_path.display()
                );
            }
            let parsed = pairing::PairingToken::decode(token_str.trim())?;
            let prev_endpoint = pairing::install_token(&parsed, &cfg, &cert_path, &pin_path)?;

            eprintln!("pairing token installed:");
            eprintln!("  daemon cert: {}", cert_path.display());
            eprintln!("  cloud pin:   {}", pin_path.display());
            eprintln!("  endpoint:    {}", parsed.endpoint);
            if let Some(prev) = prev_endpoint {
                eprintln!("  (previous endpoint was: {prev})");
            }
            if let Some(label) = parsed.customer_label {
                eprintln!("  label:       {label}");
            }
            let audit = audit::Audit::new(cfg.policy.name());
            audit.write(audit::Event::Lifecycle {
                event: "paired".into(),
                detail: format!("endpoint={}", parsed.endpoint),
            })?;
            eprintln!();
            eprintln!("Restart the daemon to begin using the new credentials.");
            Ok(())
        }
    }
}

// `Context` for the `?`-context on file reads above.
use anyhow::Context as _;
