//! Boundary-parsed data models returned by the Vault API.
//!
//! Parse-don't-validate: these types are produced exactly once, at the vault-client
//! boundary, from raw API responses. The rest of the app never touches
//! `serde_json::Value` or untyped maps.
//!
//! Value semantics mirror the Go vaultview: secret values are coerced to display
//! strings (Go JSON-marshals each value then unquotes it), and edits write string
//! values back — including the original Go wart that JSON values become strings
//! after an edit round-trip.

use std::collections::BTreeMap;

use secrecy::SecretString;

use crate::path::SecretPath;

/// A single ACL policy entry from `sys/policies/acl` listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEntry {
    /// Policy name.
    pub name: String,
}

/// ACL policy document read from `sys/policies/acl/{name}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDocument {
    /// Policy name.
    pub name: String,
    /// Policy `HCL` text.
    pub policy: String,
}

/// A single item in a KV2 list response. Directory entries keep their trailing `/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretEntry {
    /// The entry name (with trailing `/` for directories).
    pub name: SecretPath,
    /// True for directory entries.
    pub is_dir: bool,
}

impl SecretEntry {
    /// Builds a directory entry from a raw name (must end with `/`).
    #[must_use]
    pub fn dir(name: &str) -> Self {
        Self {
            name: SecretPath::new(name),
            is_dir: true,
        }
    }

    /// Builds a leaf entry from a raw name.
    #[must_use]
    pub fn leaf(name: &str) -> Self {
        Self {
            name: SecretPath::new(name),
            is_dir: false,
        }
    }
}

/// A KV2 secret: its key/value data plus version metadata.
#[derive(Debug, Clone)]
pub struct KvData {
    /// Key → display-string value (masks on `Debug`).
    pub data: BTreeMap<String, SecretString>,
    /// Version metadata that accompanies the secret.
    pub metadata: KvMetadata,
}

/// Version metadata returned with a KV2 secret (mirrors `Go` `SecretMetadata`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvMetadata {
    /// Secret version number.
    pub version: u64,
    /// True when the version was destroyed in Vault.
    pub destroyed: bool,
    /// `RFC3339` timestamp as returned by Vault (e.g. `2026-10-13T10:00:00Z`).
    pub created_time: String,
}

/// Token lookup info (from `lookup_self`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenInfo {
    /// Policies attached to the token.
    pub policies: Vec<String>,
    /// `None` when the token never expires (`Go` displays "eternal" for root tokens).
    pub expire_time: Option<String>,
}

impl TokenInfo {
    /// True when the token lives forever (`Go`: nil `expire_time` + root policy).
    #[must_use]
    pub fn is_eternal(&self) -> bool {
        self.expire_time.is_none() && self.policies.iter().any(|p| p == "root")
    }
}

/// Snapshot of `/v1/sys/health`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthInfo {
    /// True when the Vault server is sealed.
    pub sealed: bool,
    /// Vault server version, e.g. `1.18.0`.
    pub version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eternal_when_root_without_expiry() {
        let info = TokenInfo {
            policies: vec!["root".into()],
            expire_time: None,
        };
        assert!(info.is_eternal());
    }

    #[test]
    fn not_eternal_when_expiry_present() {
        let info = TokenInfo {
            policies: vec!["root".into()],
            expire_time: Some("2027-01-01T00:00:00Z".into()),
        };
        assert!(!info.is_eternal());
    }

    #[test]
    fn not_eternal_for_regular_token() {
        let info = TokenInfo {
            policies: vec!["default".into()],
            expire_time: None,
        };
        assert!(!info.is_eternal());
    }

    #[test]
    fn entry_kinds() {
        let d = SecretEntry::dir("team/");
        assert!(d.is_dir);
        let l = SecretEntry::leaf("creds");
        assert!(!l.is_dir);
    }
}
