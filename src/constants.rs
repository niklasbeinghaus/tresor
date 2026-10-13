//! Central view names, key bindings, and UI strings.
//!
//! Mirrors the Go vaultview `pkg/constants`. Everything stringly-typed that
//! crosses a module boundary lives here; never inline raw strings.

/// Fallback display value for unparseable metadata (Go `NAValue`).
pub const NA_VALUE: &str = "n/a";

/// Mask shown instead of a secret value until explicitly revealed.
pub const MASK: &str = "*****";

/// Duration before a status message auto-clears (Go: 5 seconds).
pub const STATUS_EXPIRY_SECS: u64 = 5;

/// Key bindings (parity with the Go app).
pub mod keys {
    /// `<x>` — reveal the selected secret value.
    pub const REVEAL: char = 'x';
    /// `<e>` — edit the selected secret value.
    pub const EDIT: char = 'e';
    /// `<c>` — copy the selected secret value to the clipboard.
    pub const COPY: char = 'c';
}

/// Page/view identifiers used for routing.
pub mod pages {
    /// Vault address/token configuration form (shown when env vars are missing).
    pub const CONFIG: &str = "config";
    /// Secret engines list.
    pub const ENGINES: &str = "engines";
    /// Hierarchical secret browser.
    pub const SECRETS: &str = "secrets";
    /// Secret key/value view (reveal/edit/copy/save).
    pub const SECRET_DATA: &str = "secret-data";
}

/// Display titles for the secret views.
pub mod titles {
    /// Engines view title.
    pub const ENGINES: &str = "[Secret Engines]";
    /// Secrets view title.
    pub const SECRETS: &str = "Secrets";
}

/// Environment variables the app consults at startup.
pub mod env {
    /// Vault server address.
    pub const VAULT_ADDR: &str = "VAULT_ADDR";
    /// Vault authentication token.
    pub const VAULT_TOKEN: &str = "VAULT_TOKEN";
    /// `OpenBao` server address (preferred over `VAULT_ADDR`).
    pub const BAO_ADDR: &str = "BAO_ADDR";
    /// `OpenBao` authentication token (preferred over `VAULT_TOKEN`).
    pub const BAO_TOKEN: &str = "BAO_TOKEN";
    /// CLI token store override (`bao login` writes `~/.vault-token` by default).
    pub const BAO_TOKEN_PATH: &str = "BAO_TOKEN_PATH";
}
