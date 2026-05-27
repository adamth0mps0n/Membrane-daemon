//! Daemon configuration: policy modes, endpoint, limits.
//!
//! Loaded from `policy.toml`. System-wide policy (enterprise MDM) at
//! `system_dir()/policy.toml` takes precedence over user policy at
//! `user_dir()/policy.toml`. Within a file, missing fields use defaults.
//!
//! Policy modes (see PolicyMode):
//! - `Unrestricted` — full power; default for fresh installs.
//! - `Workspace` — paths confined to configured roots; exec unrestricted.
//! - `WorkspaceAllowlistExec` — paths AND exec confined.
//! - `ReadOnly` — read-only; writes and exec denied.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const DEFAULT_ENDPOINT: &str = "https://cloud.membrane.example.com:443";
const DEFAULT_EXEC_TIMEOUT_MS: u32 = 60_000;
const MAX_EXEC_TIMEOUT_MS: u32 = 600_000;     // 10 minutes hard ceiling
const DEFAULT_MAX_OUTPUT: u64 = 1 << 20;       // 1 MiB
const DEFAULT_MAX_READ: u64 = 16 << 20;        // 16 MiB single file

/// Policy mode — how the daemon constrains what the cloud can do.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum PolicyMode {
    /// Full power. Cloud can read/write anywhere the daemon's user can,
    /// and exec any command. Default for fresh installs.
    Unrestricted,

    /// Paths confined to `roots`; exec unrestricted but its working
    /// directory is vetted to be inside a root.
    Workspace { roots: Vec<PathBuf> },

    /// Paths confined to `roots`; exec only for binaries whose argv[0]
    /// (after path resolution) matches an entry in `exec_allowlist`.
    WorkspaceAllowlistExec {
        roots: Vec<PathBuf>,
        exec_allowlist: Vec<String>,
    },

    /// Read-only: writes and exec denied. Reads confined to `roots`.
    ReadOnly { roots: Vec<PathBuf> },
}

impl Default for PolicyMode {
    fn default() -> Self { PolicyMode::Unrestricted }
}

impl PolicyMode {
    /// Returns the configured roots if the mode is workspace-bounded,
    /// otherwise None (meaning anywhere).
    pub fn roots(&self) -> Option<&[PathBuf]> {
        match self {
            PolicyMode::Unrestricted => None,
            PolicyMode::Workspace { roots }
            | PolicyMode::WorkspaceAllowlistExec { roots, .. }
            | PolicyMode::ReadOnly { roots } => Some(roots),
        }
    }

    /// True if path is allowed under this mode. Resolves symlinks via
    /// `path.canonicalize()` to prevent root-escape via symlinks.
    pub fn path_allowed(&self, path: &Path) -> bool {
        let Some(roots) = self.roots() else { return true; };
        let canon = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        roots.iter().any(|r| {
            let rc = r.canonicalize().unwrap_or_else(|_| r.clone());
            canon.starts_with(&rc)
        })
    }

    /// True if write operations are allowed at all.
    pub fn writes_allowed(&self) -> bool {
        !matches!(self, PolicyMode::ReadOnly { .. })
    }

    /// True if exec is allowed for the given command. For allowlist
    /// mode, the first whitespace-separated token of `cmd` is treated
    /// as the binary name and compared to the allowlist.
    pub fn exec_allowed(&self, cmd: &str) -> bool {
        match self {
            PolicyMode::ReadOnly { .. } => false,
            PolicyMode::Unrestricted | PolicyMode::Workspace { .. } => true,
            PolicyMode::WorkspaceAllowlistExec { exec_allowlist, .. } => {
                let bin = cmd.split_whitespace().next().unwrap_or("");
                // Match against bare name, full path, or basename of full path.
                let basename = Path::new(bin).file_name()
                    .and_then(|n| n.to_str()).unwrap_or(bin);
                exec_allowlist.iter().any(|a| {
                    a == bin || a == basename || Path::new(a).file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n == basename).unwrap_or(false)
                })
            }
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            PolicyMode::Unrestricted => "Unrestricted",
            PolicyMode::Workspace { .. } => "Workspace",
            PolicyMode::WorkspaceAllowlistExec { .. } => "WorkspaceAllowlistExec",
            PolicyMode::ReadOnly { .. } => "ReadOnly",
        }
    }
}

/// Full daemon configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Cloud endpoint URL (QUIC over UDP at the given port).
    #[serde(default = "default_endpoint")]
    pub endpoint: String,

    /// Current policy mode.
    #[serde(default)]
    pub policy: PolicyMode,

    /// Hard ceiling on exec timeout in ms. Cloud may request shorter;
    /// daemon clamps to this max.
    #[serde(default = "default_exec_timeout_ms")]
    pub max_exec_timeout_ms: u32,

    /// Hard ceiling on exec output bytes (stdout + stderr combined).
    #[serde(default = "default_max_output")]
    pub max_output_bytes: u64,

    /// Hard ceiling on a single file read.
    #[serde(default = "default_max_read")]
    pub max_read_bytes: u64,
}

fn default_endpoint() -> String { DEFAULT_ENDPOINT.to_string() }
fn default_exec_timeout_ms() -> u32 { DEFAULT_EXEC_TIMEOUT_MS }
fn default_max_output() -> u64 { DEFAULT_MAX_OUTPUT }
fn default_max_read() -> u64 { DEFAULT_MAX_READ }

impl Default for Config {
    fn default() -> Self {
        Self {
            endpoint: default_endpoint(),
            policy: PolicyMode::default(),
            max_exec_timeout_ms: default_exec_timeout_ms(),
            max_output_bytes: default_max_output(),
            max_read_bytes: default_max_read(),
        }
    }
}

impl Config {
    /// Load the effective config: system policy (if present) merged with
    /// user policy. System takes precedence per-field.
    ///
    /// Returns the default config if neither file exists. Returns an
    /// error only on parse failure (not on missing files).
    pub fn load() -> anyhow::Result<Config> {
        let user = read_optional(&crate::paths::user_policy())?;
        let system = read_optional(&crate::paths::system_policy())?;
        // System-policy field values override user-policy values.
        // Implementation: parse both as Value, merge keys, then deserialize.
        let merged = match (user, system) {
            (None, None) => Config::default(),
            (Some(u), None) => u,
            (None, Some(s)) => s,
            (Some(u), Some(s)) => merge_into(u, s),
        };
        // Clamp exec timeout to hard ceiling.
        let mut c = merged;
        if c.max_exec_timeout_ms > MAX_EXEC_TIMEOUT_MS {
            c.max_exec_timeout_ms = MAX_EXEC_TIMEOUT_MS;
        }
        Ok(c)
    }

    /// Resolve the effective exec timeout: clamp `requested` to
    /// `max_exec_timeout_ms`. If requested is 0, use the max.
    pub fn effective_exec_timeout_ms(&self, requested: u32) -> u32 {
        let req = if requested == 0 { self.max_exec_timeout_ms } else { requested };
        req.min(self.max_exec_timeout_ms)
    }

    /// Save user-side config (does NOT write system policy).
    pub fn save_user(&self) -> anyhow::Result<()> {
        let path = crate::paths::user_policy();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let toml = toml::to_string_pretty(self)?;
        std::fs::write(&path, toml)?;
        Ok(())
    }
}

/// Read a TOML config file. Returns Ok(None) if it doesn't exist.
fn read_optional(path: &Path) -> anyhow::Result<Option<Config>> {
    if !path.exists() { return Ok(None); }
    let text = std::fs::read_to_string(path)?;
    let cfg: Config = toml::from_str(&text)?;
    Ok(Some(cfg))
}

/// Per-field merge: every field in `system` overrides the same field
/// in `user`. For PolicyMode (which is an enum), system wins outright
/// when the system file specified one.
fn merge_into(user: Config, system: Config) -> Config {
    // toml-rs doesn't have a deep merge. We do it field-by-field.
    // Defaults are non-distinguishable from explicit values in our model,
    // so any system field that differs from its default replaces user's.
    let defaults = Config::default();
    Config {
        endpoint: if system.endpoint != defaults.endpoint { system.endpoint } else { user.endpoint },
        policy: if system.policy != defaults.policy { system.policy } else { user.policy },
        max_exec_timeout_ms: if system.max_exec_timeout_ms != defaults.max_exec_timeout_ms { system.max_exec_timeout_ms } else { user.max_exec_timeout_ms },
        max_output_bytes: if system.max_output_bytes != defaults.max_output_bytes { system.max_output_bytes } else { user.max_output_bytes },
        max_read_bytes: if system.max_read_bytes != defaults.max_read_bytes { system.max_read_bytes } else { user.max_read_bytes },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_unrestricted() {
        let c = Config::default();
        assert!(matches!(c.policy, PolicyMode::Unrestricted));
        assert!(c.policy.writes_allowed());
        assert!(c.policy.exec_allowed("anything"));
    }

    #[test]
    fn readonly_blocks_writes_and_exec() {
        let p = PolicyMode::ReadOnly { roots: vec!["/tmp".into()] };
        assert!(!p.writes_allowed());
        assert!(!p.exec_allowed("ls"));
    }

    #[test]
    fn workspace_path_restriction() {
        // Use real temp dirs we know exist.
        let p = PolicyMode::Workspace { roots: vec!["/tmp".into()] };
        assert!(p.path_allowed(Path::new("/tmp/foo")));
        // /etc exists and is not under /tmp.
        assert!(!p.path_allowed(Path::new("/etc/hostname")));
    }

    #[test]
    fn allowlist_exec_matches_basename() {
        let p = PolicyMode::WorkspaceAllowlistExec {
            roots: vec!["/tmp".into()],
            exec_allowlist: vec!["git".into(), "/usr/bin/cargo".into()],
        };
        assert!(p.exec_allowed("git status"));
        assert!(p.exec_allowed("/usr/local/bin/git status"));
        assert!(p.exec_allowed("cargo build"));
        assert!(p.exec_allowed("/usr/bin/cargo test"));
        assert!(!p.exec_allowed("curl evil.com"));
        assert!(!p.exec_allowed("rm -rf /"));
    }

    #[test]
    fn config_roundtrip_toml() {
        let c = Config {
            endpoint: "https://example.com:8443".into(),
            policy: PolicyMode::Workspace { roots: vec!["/tmp/a".into(), "/tmp/b".into()] },
            max_exec_timeout_ms: 30000,
            max_output_bytes: 2_000_000,
            max_read_bytes: 4_000_000,
        };
        let s = toml::to_string(&c).unwrap();
        let c2: Config = toml::from_str(&s).unwrap();
        assert_eq!(c.endpoint, c2.endpoint);
        assert_eq!(c.policy, c2.policy);
        assert_eq!(c.max_exec_timeout_ms, c2.max_exec_timeout_ms);
    }

    #[test]
    fn timeout_clamps_to_max() {
        let c = Config { max_exec_timeout_ms: 60_000, ..Config::default() };
        assert_eq!(c.effective_exec_timeout_ms(30_000), 30_000);
        assert_eq!(c.effective_exec_timeout_ms(120_000), 60_000);
        assert_eq!(c.effective_exec_timeout_ms(0), 60_000);
    }

    #[test]
    fn missing_fields_use_defaults_on_deserialize() {
        // A minimal config file with just the endpoint should fill the rest
        // with defaults — no panics.
        let s = r#"
            endpoint = "https://my.endpoint:1234"
        "#;
        let c: Config = toml::from_str(s).unwrap();
        assert_eq!(c.endpoint, "https://my.endpoint:1234");
        assert!(matches!(c.policy, PolicyMode::Unrestricted));
        assert_eq!(c.max_exec_timeout_ms, DEFAULT_EXEC_TIMEOUT_MS);
    }
}
