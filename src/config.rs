//! Runtime configuration loaded from `BAO_`/`VAULT_` environment variables and
//! the CLI token file (`OpenBao` and `HashiCorp` Vault CLI compatible).

use std::path::PathBuf;

use secrecy::{ExposeSecret as _, SecretString};

use crate::constants::env::{BAO_ADDR, BAO_TOKEN, BAO_TOKEN_PATH, VAULT_ADDR, VAULT_TOKEN};

/// Runtime configuration: Vault address and token.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Config {
    /// Vault server address without one trailing slash.
    pub addr: String,
    /// Vault token used for API calls.
    pub token: SecretString,
}

impl PartialEq for Config {
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr && self.token.expose_secret() == other.token.expose_secret()
    }
}

impl Eq for Config {}

impl Config {
    /// Builds runtime configuration and normalizes the Vault address.
    pub fn new(addr: impl Into<String>, token: impl Into<String>) -> Self {
        let addr = addr.into();
        Self {
            addr: trim_one_trailing_slash(&addr).to_owned(),
            token: SecretString::from(token.into()),
        }
    }

    /// Loads runtime configuration: address from `BAO_ADDR` (fallback
    /// `VAULT_ADDR`), token from `BAO_TOKEN` (fallback `VAULT_TOKEN`), and as a
    /// last resort the CLI token file (`BAO_TOKEN_PATH`, then `VAULT_TOKEN_PATH`,
    /// then `~/.vault-token` — the file `bao login` writes on success).
    ///
    /// Returns `None` when no address/token pair is found; the app then shows
    /// the configuration modal.
    pub fn from_env() -> Option<Self> {
        let addr = bao_var(BAO_ADDR).or_else(|| bao_var(VAULT_ADDR));
        let token = bao_var(BAO_TOKEN)
            .or_else(|| bao_var(VAULT_TOKEN))
            .or_else(read_cli_token);
        from_vars(addr.as_deref(), token.as_deref())
    }

    /// Returns the normalized Vault address.
    #[allow(
        clippy::incompatible_msrv,
        reason = "Cargo.toml rust-version is 1.85; const String::as_str is required for the public accessor"
    )]
    pub const fn addr(&self) -> &str {
        self.addr.as_str()
    }

    /// Returns the exposed Vault token.
    pub fn token(&self) -> &str {
        self.token.expose_secret()
    }
}

fn from_vars(addr: Option<&str>, token: Option<&str>) -> Option<Config> {
    let addr = non_empty_trimmed(addr)?;
    let token = non_empty_trimmed(token)?;
    Some(Config::new(addr, token))
}

/// Reads an environment variable with `OpenBao` CLI semantics: a `BAO_*` variable
/// wins over its `VAULT_*` counterpart even when it is set to the empty string.
/// Non-`BAO_*` names are read as-is (they are the fallback targets).
fn bao_var(name: &str) -> Option<String> {
    std::env::var(name).ok().or_else(|| {
        name.strip_prefix("BAO_")
            .and_then(|upstream| std::env::var(format!("VAULT_{upstream}")).ok())
    })
}

/// Reads the first non-empty token from the CLI token store.
fn read_cli_token() -> Option<String> {
    read_first_token(&cli_token_paths())
}

/// Resolves the CLI token candidate paths in precedence order:
/// `BAO_TOKEN_PATH`, `VAULT_TOKEN_PATH`, `~/.vault-token`.
fn cli_token_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(path) = env_path(BAO_TOKEN_PATH) {
        paths.push(path);
    }
    if let Some(path) = env_path("VAULT_TOKEN_PATH") {
        paths.push(path);
    }
    if let Some(home) = home_dir() {
        paths.push(home.join(".vault-token"));
    }
    paths
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from)
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

/// Returns the trimmed contents of the first existing, non-empty token file.
fn read_first_token(paths: &[PathBuf]) -> Option<String> {
    paths.iter().find_map(|path| {
        std::fs::read_to_string(path)
            .ok()
            .map(|raw| raw.trim().to_owned())
            .filter(|token| !token.is_empty())
    })
}

fn non_empty_trimmed(value: Option<&str>) -> Option<&str> {
    value.and_then(|raw| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn trim_one_trailing_slash(value: &str) -> &str {
    value.strip_suffix('/').map_or(value, |trimmed| trimmed)
}

#[cfg(test)]
mod tests {
    use super::{Config, bao_var, from_vars, read_first_token};
    use crate::test_support::env_lock;

    #[test]
    fn test_new_strips_one_trailing_slash_when_addr_ends_with_single_slash() {
        // Given: a Vault address with one trailing slash.
        let addr = "https://vault:8200/";

        // When: the runtime config is built.
        let cfg = Config::new(addr, "token");

        // Then: exactly that trailing slash is removed.
        assert_eq!(cfg.addr(), "https://vault:8200");
    }

    #[test]
    fn test_new_strips_one_trailing_slash_when_addr_ends_with_multiple_slashes() {
        // Given: a Vault address with two trailing slashes.
        let addr = "a/b//";

        // When: the runtime config is built.
        let cfg = Config::new(addr, "token");

        // Then: Go TrimSuffix parity removes only one slash.
        assert_eq!(cfg.addr(), "a/b/");
    }

    #[test]
    fn test_from_vars_returns_config_when_both_values_are_present() {
        // Given: both env values are present with incidental whitespace.
        let addr = Some("  https://vault:8200/  ");
        let token = Some("  dev-token  ");

        // When: the injectable env parser reads the values.
        let cfg = from_vars(addr, token).expect("present values should parse");

        // Then: whitespace is trimmed and the address is normalized.
        assert_eq!(cfg.addr(), "https://vault:8200");
        assert_eq!(cfg.token(), "dev-token");
    }

    #[test]
    fn test_from_vars_returns_none_when_addr_is_missing() {
        // Given: VAULT_ADDR is absent.
        let addr = None;
        let token = Some("dev-token");

        // When: the injectable env parser reads the values.
        let cfg = from_vars(addr, token);

        // Then: the app has no usable config.
        assert_eq!(cfg, None);
    }

    #[test]
    fn test_from_vars_returns_none_when_token_is_missing() {
        // Given: VAULT_TOKEN is absent.
        let addr = Some("https://vault:8200");
        let token = None;

        // When: the injectable env parser reads the values.
        let cfg = from_vars(addr, token);

        // Then: the app has no usable config.
        assert_eq!(cfg, None);
    }

    #[test]
    fn test_from_vars_returns_none_when_addr_is_whitespace_only() {
        // Given: VAULT_ADDR contains no non-whitespace characters.
        let addr = Some("   ");
        let token = Some("dev-token");

        // When: the injectable env parser reads the values.
        let cfg = from_vars(addr, token);

        // Then: the app has no usable config.
        assert_eq!(cfg, None);
    }

    #[test]
    fn test_from_vars_returns_none_when_token_is_whitespace_only() {
        // Given: VAULT_TOKEN contains no non-whitespace characters.
        let addr = Some("https://vault:8200");
        let token = Some("   ");

        // When: the injectable env parser reads the values.
        let cfg = from_vars(addr, token);

        // Then: the app has no usable config.
        assert_eq!(cfg, None);
    }

    #[test]
    fn test_read_first_token_returns_trimmed_contents_when_file_exists() {
        // Given: a token file containing a token surrounded by whitespace.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".vault-token");
        std::fs::write(&path, "  platform-oidc-token  \n").expect("write token file");

        // When: the token store is read.
        let token = read_first_token(std::slice::from_ref(&path));

        // Then: whitespace is trimmed and the token returned.
        assert_eq!(token.as_deref(), Some("platform-oidc-token"));
    }

    #[test]
    fn test_read_first_token_skips_missing_and_empty_files() {
        // Given: one missing path and one empty file.
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("missing");
        let empty = dir.path().join("empty");
        std::fs::write(&empty, "  \n").expect("write empty token file");

        // When: the token store is read.
        let token = read_first_token(&[missing, empty]);

        // Then: no token is produced.
        assert_eq!(token, None);
    }

    #[test]
    fn test_read_first_token_uses_first_existing_path() {
        // Given: an empty first candidate and a populated second candidate.
        let dir = tempfile::tempdir().expect("tempdir");
        let first = dir.path().join("empty");
        let second = dir.path().join(".vault-token");
        std::fs::write(&first, "  ").expect("write first");
        std::fs::write(&second, "real-token").expect("write second");

        // When: the token store is read.
        let token = read_first_token(&[first, second]);

        // Then: the populated file wins (empty candidates are skipped).
        assert_eq!(token.as_deref(), Some("real-token"));
    }

    #[test]
    fn test_from_env_uses_token_file_when_env_token_is_missing() {
        // Given: env token vars absent, address set, and a token file present.
        let _lock = env_lock();
        for name in ["BAO_TOKEN", "VAULT_TOKEN", "VAULT_ADDR"] {
            env_remove(name);
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let token_path = dir.path().join("token");
        std::fs::write(&token_path, "file-token").expect("write token file");
        env_set("BAO_ADDR", "https://openbao:8200");
        env_set("BAO_TOKEN_PATH", &token_path);

        // When: config is loaded from the environment.
        let cfg = Config::from_env();

        // Then: the address comes from env and the token from the file.
        assert_eq!(cfg.as_ref().map(Config::addr), Some("https://openbao:8200"));
        assert_eq!(
            cfg.map(|c| c.token().to_owned()),
            Some("file-token".to_owned())
        );
    }

    #[test]
    fn test_bao_var_prefers_bao_even_when_empty() {
        // Given: both BAO_ADDR (empty) and VAULT_ADDR set.
        let _lock = env_lock();
        env_set("BAO_ADDR", "");
        env_set("VAULT_ADDR", "https://vault:8200");

        // When: the variable is read.
        let value = bao_var("BAO_ADDR");

        // Then: the (empty) BAO_ value wins, mirroring the OpenBao CLI.
        assert_eq!(value, Some(String::new()));
    }

    #[test]
    fn test_bao_var_falls_back_to_vault_when_bao_is_unset() {
        // Given: only VAULT_ADDR set.
        let _lock = env_lock();
        env_remove("BAO_ADDR");
        env_set("VAULT_ADDR", "https://vault:8200");

        // When: the variable is read.
        let value = bao_var("BAO_ADDR");

        // Then: the VAULT_ counterpart is used.
        assert_eq!(value.as_deref(), Some("https://vault:8200"));
    }

    /// Serializes tests that mutate the process environment.
    fn env_set<K: AsRef<std::ffi::OsStr>, V: AsRef<std::ffi::OsStr>>(name: K, value: V) {
        // SAFETY: callers hold `env_lock`, serializing all env writes in tests;
        // no other thread reads or writes these variables concurrently.
        unsafe { std::env::set_var(name, value) };
    }

    fn env_remove(name: &str) {
        // SAFETY: callers hold `env_lock`, serializing all env writes in tests.
        unsafe { std::env::remove_var(name) };
    }
}
