//! Named connection profiles loaded from `~/.config/tresor/config.toml`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

/// Where a profile's token comes from. Raw tokens are never stored inline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenSource {
    /// Read the token from this file (leading `~` expanded to the home dir).
    File(std::path::PathBuf),
    /// Run this command and take trimmed stdout as the token.
    Command(String),
}

/// A named connection profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// Profile name (the `[profiles.<name>]` key).
    pub name: String,
    /// Vault server address.
    pub addr: String,
    /// Where the token comes from.
    pub token_source: TokenSource,
}

/// All configured profiles plus the optional default profile name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Profiles {
    /// Profiles sorted alphabetically by name (parsed from a BTreeMap).
    pub profiles: Vec<Profile>,
    /// Optional `current` profile name to connect with at startup.
    pub current: Option<String>,
}

impl Profiles {
    /// Returns the profile named `name`, if present.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Profile> {
        self.profiles.iter().find(|profile| profile.name == name)
    }

    /// Returns the profile named by `current`, if it resolves.
    #[must_use]
    pub fn current(&self) -> Option<&Profile> {
        self.current.as_deref().and_then(|name| self.get(name))
    }

    /// True when no profiles are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    /// Every profile name in config order.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.profiles
            .iter()
            .map(|profile| profile.name.as_str())
            .collect()
    }
}

impl Profile {
    /// Builds a deferred connect request (token resolved later).
    #[must_use]
    pub fn to_request(&self) -> ConnectRequest {
        ConnectRequest {
            profile_name: Some(self.name.clone()),
            addr: self.addr.clone(),
            token_source: self.token_source.clone(),
        }
    }
}

/// A request to (re)connect; the token resolves asynchronously so a slow
/// `token_command` never blocks the UI thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    /// Profile name, or `None` for an explicit request.
    pub profile_name: Option<String>,
    /// Vault server address.
    pub addr: String,
    /// Where the token comes from.
    pub token_source: TokenSource,
}

impl ConnectRequest {
    /// Builds a request from an explicit address and token source.
    #[must_use]
    pub fn new(addr: impl Into<String>, token_source: TokenSource) -> Self {
        Self {
            profile_name: None,
            addr: addr.into(),
            token_source,
        }
    }

    /// Resolves the token and returns the runtime config.
    ///
    /// # Errors
    /// Returns [`ProfileError`] when token resolution fails.
    pub async fn resolve_config(self) -> Result<crate::config::Config, ProfileError> {
        let token = match self.token_source {
            TokenSource::File(path) => {
                let raw = std::fs::read_to_string(&path)
                    .map_err(|_| ProfileError::TokenFile { path: path.clone() })?;
                let token = raw.trim();
                if token.is_empty() {
                    return Err(ProfileError::TokenFile { path });
                }
                token.to_owned()
            }
            TokenSource::Command(command) => {
                let output =
                    tokio::time::timeout(Duration::from_secs(10), run_shell(&command).output())
                        .await
                        .map_err(|_| ProfileError::CommandTimeout)?
                        .map_err(|_| {
                            ProfileError::CommandFailed("command execution failed".to_owned())
                        })?;

                if !output.status.success() {
                    let stderr = output.stderr;
                    let message = command_failure_message(output.status.code(), &stderr);
                    return Err(ProfileError::CommandFailed(message));
                }

                let stdout = String::from_utf8_lossy(&output.stdout);
                let token = stdout.trim();
                if token.is_empty() {
                    return Err(ProfileError::EmptyToken);
                }
                token.to_owned()
            }
        };
        Ok(crate::config::Config::new(self.addr, token))
    }
}

/// Profile load/resolution error.
#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    /// The token file could not be read (missing, unreadable, or empty).
    #[error("token file `{path}` could not be read")]
    TokenFile {
        /// Path of the unreadable or empty token file.
        path: std::path::PathBuf,
    },
    /// The token command exited non-zero.
    #[error("token command failed: {0}")]
    CommandFailed(String),
    /// The token command produced no output.
    #[error("token command produced no output")]
    EmptyToken,
    /// The token command exceeded the timeout.
    #[error("token command timed out")]
    CommandTimeout,
}

/// Returns the tresor config dir (`$TRESOR_CONFIG`, else `~/.config/tresor`).
#[must_use]
pub fn config_dir() -> Option<std::path::PathBuf> {
    if let Some(dir) = std::env::var_os("TRESOR_CONFIG") {
        return Some(PathBuf::from(dir));
    }
    home_dir().map(|home| home.join(".config").join("tresor"))
}

/// Returns `<config_dir>/config.toml`.
#[must_use]
pub fn config_path() -> Option<std::path::PathBuf> {
    config_dir().map(|dir| dir.join("config.toml"))
}

/// Loads profiles; `None` when there is no usable config.
#[must_use]
pub fn load_profiles() -> Option<Profiles> {
    let path = config_path()?;
    if !path.is_file() {
        return None;
    }
    let raw = std::fs::read_to_string(&path).ok()?;
    match resolve_profiles(&raw) {
        Ok(profiles) => Some(profiles),
        Err(err) => {
            tracing::warn!(?path, %err, "ignoring unparsable tresor profile config");
            None
        }
    }
}

/// Parses profiles from raw TOML (testable seam); invalid entries skipped with
/// a `tracing::warn!`.
///
/// # Errors
/// Returns `toml` parse errors for invalid top-level document syntax.
pub fn resolve_profiles(raw: &str) -> Result<Profiles, toml::de::Error> {
    let parsed: FileConfig = toml::from_str(raw)?;
    let mut profiles = Vec::new();

    for (name, entry) in parsed.profiles {
        let addr = entry.addr.trim();
        if addr.is_empty() {
            tracing::warn!(profile = %name, "skipping profile with empty addr");
            continue;
        }

        if entry.token.is_some() {
            tracing::warn!(profile = %name, "skipping profile that uses unsupported inline token");
            continue;
        }

        let token_file = entry
            .token_file
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let token_command = entry
            .token_command
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());

        let Some(token_source) = (match (token_file, token_command) {
            (Some(file), None) => Some(TokenSource::File(expand_tilde(file))),
            (None, Some(command)) => Some(TokenSource::Command(command.to_owned())),
            (Some(_), Some(_)) => {
                tracing::warn!(
                    profile = %name,
                    "skipping profile with both token_file and token_command"
                );
                None
            }
            (None, None) => {
                tracing::warn!(
                    profile = %name,
                    "skipping profile without token_file or token_command"
                );
                None
            }
        }) else {
            continue;
        };

        profiles.push(Profile {
            name,
            addr: addr.to_owned(),
            token_source,
        });
    }

    Ok(Profiles {
        profiles,
        current: parsed.current,
    })
}

#[derive(Debug, Default, Deserialize)]
struct FileConfig {
    #[serde(default)]
    current: Option<String>,
    #[serde(default)]
    profiles: BTreeMap<String, ProfileEntry>,
}

#[derive(Debug, Default, Deserialize)]
struct ProfileEntry {
    #[serde(default)]
    addr: String,
    #[serde(default)]
    token_file: Option<String>,
    #[serde(default)]
    token_command: Option<String>,
    #[serde(default)]
    token: Option<String>,
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from)
}

fn expand_tilde(raw: &str) -> PathBuf {
    if raw == "~" {
        return home_dir().unwrap_or_else(|| PathBuf::from(raw));
    }

    if let Some(rest) = raw.strip_prefix("~/") {
        return home_dir().map_or_else(|| PathBuf::from(raw), |home| home.join(rest));
    }

    PathBuf::from(raw)
}

fn truncate_for_error(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_owned();
    }
    let mut end = 0;
    for (index, ch) in value.char_indices().take(max_chars) {
        end = index + ch.len_utf8();
    }
    let mut truncated = value[..end].to_owned();
    truncated.push('…');
    truncated
}

fn command_failure_message(code: Option<i32>, stderr: &[u8]) -> String {
    let stderr_trimmed = String::from_utf8_lossy(stderr).trim().to_owned();
    if !stderr_trimmed.is_empty() {
        return truncate_for_error(&stderr_trimmed, 200);
    }

    code.map_or_else(
        || "terminated by signal".to_owned(),
        |exit_code| format!("exit status {exit_code}"),
    )
}

#[cfg(unix)]
fn run_shell(command: &str) -> tokio::process::Command {
    let mut shell = tokio::process::Command::new("sh");
    shell.arg("-c").arg(command).kill_on_drop(true);
    shell
}

#[cfg(windows)]
fn run_shell(command: &str) -> tokio::process::Command {
    let mut shell = tokio::process::Command::new("cmd");
    shell.arg("/C").arg(command).kill_on_drop(true);
    shell
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_profiles_parses_current_with_valid_token_file_profile() {
        // Given: one valid profile with `current` pointing to it.
        let raw = r#"
            current = "dev"
            [profiles.dev]
            addr = "http://127.0.0.1:8200"
            token_file = "~/.vault-token"
        "#;

        // When: profiles are parsed.
        let profiles = resolve_profiles(raw).expect("profiles should parse");

        // Then: current resolves and token source is file-based.
        assert_eq!(profiles.current.as_deref(), Some("dev"));
        assert_eq!(profiles.profiles.len(), 1);
        assert_eq!(
            profiles.current().map(|profile| profile.name.as_str()),
            Some("dev")
        );
        assert!(matches!(
            profiles
                .profiles
                .first()
                .map(|profile| &profile.token_source),
            Some(TokenSource::File(_))
        ));
    }

    #[test]
    fn test_resolve_profiles_skips_inline_token_and_current_then_resolves_none() {
        // Given: `current` points to a profile that uses forbidden inline token.
        let raw = r#"
            current = "dev"
            [profiles.dev]
            addr = "http://127.0.0.1:8200"
            token = "raw-token"
        "#;

        // When: profiles are parsed.
        let profiles = resolve_profiles(raw).expect("profiles should parse");

        // Then: the invalid profile is skipped and `current()` resolves to none.
        assert!(profiles.is_empty());
        assert_eq!(profiles.current.as_deref(), Some("dev"));
        assert_eq!(profiles.current(), None);
    }

    #[test]
    fn test_resolve_profiles_skips_profiles_with_both_or_neither_token_source() {
        // Given: one profile defines both sources and another defines neither.
        let raw = r#"
            [profiles.both]
            addr = "http://127.0.0.1:8200"
            token_file = "~/.vault-token"
            token_command = "bao print token"

            [profiles.neither]
            addr = "http://127.0.0.1:8200"
        "#;

        // When: profiles are parsed.
        let profiles = resolve_profiles(raw).expect("profiles should parse");

        // Then: both invalid profiles are skipped.
        assert!(profiles.is_empty());
    }

    #[test]
    fn test_resolve_profiles_expands_tilde_for_token_file() {
        // Given: a token_file path with leading `~`.
        let raw = r#"
            [profiles.dev]
            addr = "http://127.0.0.1:8200"
            token_file = "~/.vault-token"
        "#;

        // When: profiles are parsed.
        let profiles = resolve_profiles(raw).expect("profiles should parse");

        // Then: the token file path is stored expanded when home is known.
        let source = profiles
            .profiles
            .first()
            .map(|profile| profile.token_source.clone())
            .expect("profile should exist");
        match source {
            TokenSource::File(path) => {
                let expected = home_dir().map_or_else(
                    || PathBuf::from("~/.vault-token"),
                    |home| home.join(".vault-token"),
                );
                assert_eq!(path, expected);
            }
            TokenSource::Command(_) => panic!("expected file source"),
        }
    }

    #[tokio::test]
    async fn test_resolve_config_file_trims_token_contents() {
        // Given: a token file containing extra whitespace around the token.
        let dir = tempfile::tempdir().expect("tempdir");
        let token_path = dir.path().join("token");
        std::fs::write(&token_path, "  file-token  \n").expect("write token file");
        let request = ConnectRequest::new("http://127.0.0.1:8200/", TokenSource::File(token_path));

        // When: runtime config is resolved.
        let config = request
            .resolve_config()
            .await
            .expect("file token should resolve");

        // Then: token is trimmed and address normalized by `Config::new`.
        assert_eq!(config.addr(), "http://127.0.0.1:8200");
        assert_eq!(config.token(), "file-token");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_resolve_config_command_returns_trimmed_stdout() {
        // Given: a command that prints a token with surrounding whitespace.
        let request = ConnectRequest::new(
            "http://127.0.0.1:8200",
            TokenSource::Command("printf '  cmd-token  \\n'".to_owned()),
        );

        // When: runtime config is resolved.
        let config = request
            .resolve_config()
            .await
            .expect("command token should resolve");

        // Then: stdout is trimmed and used as token.
        assert_eq!(config.token(), "cmd-token");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_resolve_config_command_returns_failure_on_non_zero_exit() {
        // Given: a command that writes stderr and exits non-zero.
        let request = ConnectRequest::new(
            "http://127.0.0.1:8200",
            TokenSource::Command("printf 'boom' >&2; exit 3".to_owned()),
        );

        // When: runtime config resolution runs.
        let result = request.resolve_config().await;

        // Then: command failure is reported.
        assert!(
            matches!(result, Err(ProfileError::CommandFailed(message)) if message.contains("boom"))
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_resolve_config_command_returns_empty_token_for_blank_stdout() {
        // Given: a command that exits zero but emits no stdout.
        let request = ConnectRequest::new(
            "http://127.0.0.1:8200",
            TokenSource::Command("true".to_owned()),
        );

        // When: runtime config resolution runs.
        let result = request.resolve_config().await;

        // Then: empty command output is rejected.
        assert!(matches!(result, Err(ProfileError::EmptyToken)));
    }
}
