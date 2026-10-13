//! Vault API boundary and typed error surface.
#![allow(
    clippy::mod_module_files,
    reason = "project plan requires src/vault/mod.rs"
)]

use std::collections::BTreeMap;
use std::future::Future;

pub use self::client::VaultClient;
use crate::model::{HealthInfo, KvData, PolicyDocument, PolicyEntry, SecretEntry, TokenInfo};
use crate::path::SecretPath;

pub mod client;

/// Errors from Vault interactions, all the way to the UI status line.
#[allow(clippy::exhaustive_enums, reason = "closed UI-facing error contract")]
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VaultError {
    /// The client could not connect to Vault or an operation timed out.
    #[error("connection error: {0}")]
    Connection(String),
    /// Vault returned a non-success API response.
    #[error("vault API error: {status} on {path}: {detail}")]
    Api {
        /// HTTP status returned by Vault.
        status: u16,
        /// Vault endpoint path associated with the failure.
        path: String,
        /// UI-safe response detail.
        detail: String,
    },
    /// Vault returned a response that did not match the expected shape.
    #[error("unexpected response: {0}")]
    Parse(String),
}

impl VaultError {
    /// Returns the HTTP status for API errors.
    #[must_use]
    pub const fn status(&self) -> Option<u16> {
        match self {
            Self::Api {
                status,
                path: _,
                detail: _,
            } => Some(*status),
            Self::Connection(_) | Self::Parse(_) => None,
        }
    }

    /// Returns a UI-safe one-line error message (omits empty API detail).
    #[must_use]
    pub fn message(&self) -> String {
        let message = match self {
            Self::Api {
                status,
                path,
                detail,
            } => {
                let mut msg = format!("vault API error: {status} on {path}");
                if !detail.is_empty() {
                    msg.push_str(": ");
                    msg.push_str(detail);
                }
                msg
            }
            Self::Connection(_) | Self::Parse(_) => self.to_string(),
        };
        message.replace(['\n', '\r'], " ")
    }
}

/// Vault API boundary with parity to the Go `VaultSvc` interface.
pub trait VaultApi: Send + Sync {
    /// Reads mounted secret engines.
    fn read_secret_engines(
        &self,
    ) -> impl Future<Output = Result<Vec<SecretEntry>, VaultError>> + Send;

    /// Lists KV2 child paths under `path` inside `mount`.
    fn list_kv_secrets(
        &self,
        mount: &SecretPath,
        path: &SecretPath,
    ) -> impl Future<Output = Result<Vec<SecretEntry>, VaultError>> + Send;

    /// Reads one KV2 secret.
    fn read_kv_secret(
        &self,
        mount: &SecretPath,
        path: &SecretPath,
    ) -> impl Future<Output = Result<KvData, VaultError>> + Send;

    /// Writes string data as a new KV2 secret version.
    fn write_kv_secret(
        &self,
        mount: &SecretPath,
        path: &SecretPath,
        data: &BTreeMap<String, String>,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    /// Reads information about the active token.
    fn read_token_info(&self) -> impl Future<Output = Result<TokenInfo, VaultError>> + Send;

    /// Reads Vault health status.
    fn sys_health(&self) -> impl Future<Output = Result<HealthInfo, VaultError>> + Send;

    /// Deletes a KV2 secret entirely (metadata delete — removes it from listings).
    fn delete_kv_secret_metadata(
        &self,
        mount: &SecretPath,
        path: &SecretPath,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;

    /// Reads the capabilities the active token holds on the given API paths
    /// (`sys/capabilities-self`) — used to gate write commands on permission.
    fn capabilities_self(
        &self,
        paths: &[String],
    ) -> impl Future<Output = Result<BTreeMap<String, Vec<String>>, VaultError>> + Send;

    /// Lists ACL policies from `sys/policies/acl`.
    fn list_acl_policies(
        &self,
    ) -> impl Future<Output = Result<Vec<PolicyEntry>, VaultError>> + Send;

    /// Reads one ACL policy document from `sys/policies/acl/{name}`.
    fn read_acl_policy(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<PolicyDocument, VaultError>> + Send;

    /// Writes an ACL policy document to `sys/policies/acl/{name}`.
    fn write_acl_policy(
        &self,
        name: &str,
        policy: &str,
    ) -> impl Future<Output = Result<(), VaultError>> + Send;
}

/// Percent-encodes an ACL policy name for use as a single URL path segment.
pub(crate) fn encode_acl_policy_name(name: &str) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::new();
    for byte in name.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            write!(encoded, "%{byte:02X}").ok();
        }
    }
    encoded
}
