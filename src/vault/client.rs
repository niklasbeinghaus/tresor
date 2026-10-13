//! `vaultrs`-backed Vault API client.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use base64::Engine as _;
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::Value;
use vaultrs::client::{VaultClient as InnerVaultClient, VaultClientSettingsBuilder};
use vaultrs::error::ClientError;

use super::{VaultApi, VaultError, encode_acl_policy_name};
use crate::constants::NA_VALUE;
use crate::model::{
    HealthInfo, KvData, KvMetadata, PolicyDocument, PolicyEntry, SecretEntry, TokenInfo,
};
use crate::path::SecretPath;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const ERROR_DETAIL_LIMIT: usize = 200;

/// Vault client implemented by the `vaultrs` crate, with a direct HTTP
/// fallback for the lenient `/v1/sys/health` probe (`OpenBao` compatibility).
pub struct VaultClient {
    inner: InnerVaultClient,
    addr: String,
    token: SecretString,
    http: reqwest::Client,
}

impl fmt::Debug for VaultClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultClient").finish_non_exhaustive()
    }
}

impl VaultClient {
    /// Builds a Vault/OpenBao client from an HTTP(S) address and token.
    pub fn connect(addr: &str, token: &str) -> Result<Self, VaultError> {
        let settings = VaultClientSettingsBuilder::default()
            .address(addr)
            .token(token)
            .timeout(Some(REQUEST_TIMEOUT))
            .build()
            .map_err(|err| VaultError::Connection(err.to_string()))?;
        let inner = InnerVaultClient::new(settings)
            .map_err(|err| VaultError::Connection(err.to_string()))?;
        Ok(Self {
            inner,
            addr: addr.to_owned(),
            token: SecretString::from(token),
            http: reqwest::Client::new(),
        })
    }

    async fn with_timeout<T>(
        future: impl std::future::Future<Output = Result<T, ClientError>>,
        path: &str,
    ) -> Result<T, VaultError> {
        tokio::time::timeout(REQUEST_TIMEOUT, future)
            .await
            .map_or_else(
                |_| Err(VaultError::Connection("timed out".to_owned())),
                |result| result.map_err(|err| map_client_error(err, path)),
            )
    }

    /// Sends a raw Vault/OpenBao request and returns the JSON envelope.
    ///
    /// The body is read as text first, then parsed: Vault error envelopes carry
    /// the detail in `errors[0]`, but a gateway may answer an error status with
    /// a non-JSON body (e.g. a `text/plain` 400) — that raw text becomes the
    /// error detail instead of a misattributed JSON decode failure.
    async fn raw_json(
        http: reqwest::Client,
        url: &str,
        method: reqwest::Method,
        token: &str,
        error_path: &str,
    ) -> Result<Value, VaultError> {
        Self::raw_request(
            http.request(method, url).header("X-Vault-Token", token),
            error_path,
        )
        .await
    }

    /// POSTs a JSON body and returns the JSON envelope (same lenient rules).
    async fn raw_json_post(
        http: reqwest::Client,
        url: &str,
        token: &str,
        error_path: &str,
        body: &Value,
    ) -> Result<Value, VaultError> {
        Self::raw_request(
            http.post(url).header("X-Vault-Token", token).json(body),
            error_path,
        )
        .await
    }

    /// Sends a prepared request and returns the parsed envelope or a typed error.
    ///
    /// The body is read as text first, then parsed: Vault error envelopes carry
    /// the detail in `errors[0]`, but a gateway may answer an error status with
    /// a non-JSON body (e.g. a `text/plain` 400) — that raw text becomes the
    /// error detail instead of a misattributed JSON decode failure.
    async fn raw_request(
        request: reqwest::RequestBuilder,
        error_path: &str,
    ) -> Result<Value, VaultError> {
        let response = tokio::time::timeout(REQUEST_TIMEOUT, request.send())
            .await
            .map_err(|_| VaultError::Connection("timed out".to_owned()))?
            .map_err(|err| VaultError::Connection(err.to_string()))?;
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|err| VaultError::Connection(err.to_string()))?;
        if status.is_success() {
            if text.trim().is_empty() {
                // 204 No Content (e.g. KV2 metadata delete) has no envelope.
                return Ok(Value::Null);
            }
            return serde_json::from_str(&text).map_err(|err| VaultError::Parse(err.to_string()));
        }
        let detail = serde_json::from_str::<Value>(&text).map_or_else(
            // Non-JSON error body (e.g. a gateway's text/plain 400): use the raw
            // text as the detail instead of a misattributed JSON decode failure.
            |_| truncate_detail(&text),
            |body| error_detail_from_body(&body),
        );
        Err(VaultError::Api {
            status: status.as_u16(),
            path: error_path.to_owned(),
            detail,
        })
    }
}

#[allow(
    clippy::manual_async_fn,
    reason = "VaultApi futures must be Send for tokio::spawn; async fn cannot express that contract here"
)]
impl VaultApi for VaultClient {
    fn read_secret_engines(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<SecretEntry>, VaultError>> + Send {
        async move {
            let mounts =
                Self::with_timeout(vaultrs::sys::mount::list(&self.inner), "sys/mounts").await;
            match mounts {
                Ok(mounts) => {
                    let mut entries = mounts
                        .keys()
                        .map(|name| SecretEntry::leaf(strip_trailing_slash(name)))
                        .collect::<Vec<_>>();
                    entries.sort_by(|left, right| left.name.cmp(&right.name));
                    Ok(entries)
                }
                Err(VaultError::Api {
                    status: 403 | 404, ..
                }) => Ok(Vec::new()),
                Err(err) => Err(err),
            }
        }
    }

    fn list_kv_secrets(
        &self,
        mount: &SecretPath,
        path: &SecretPath,
    ) -> impl std::future::Future<Output = Result<Vec<SecretEntry>, VaultError>> + Send {
        // Raw LIST with a GET ?list=true fallback: some production gateways
        // reject the LIST verb (observed 400 over HTTP/1.1); Vault and OpenBao
        // both accept GET {path}?list=true instead. Kept lenient for OpenBao
        // response variants (Vault clients must tolerate missing fields).
        let url = format!(
            "{}/v1/{}/metadata/{}",
            self.addr,
            mount.as_str(),
            path.as_str()
        );
        let api_path = format!("{}/metadata/{}", mount.as_str(), path.as_str());
        let http = self.http.clone();
        let token = self.token.expose_secret().to_owned();
        async move {
            let method = reqwest::Method::from_bytes(b"LIST")
                .map_err(|err| VaultError::Connection(err.to_string()))?;
            let body = match Self::raw_json(http.clone(), &url, method, &token, &api_path).await {
                Ok(body) => body,
                Err(VaultError::Api {
                    status: 400 | 403 | 405,
                    ..
                }) => {
                    let fallback_url = format!("{url}?list=true");
                    Self::raw_json(http, &fallback_url, reqwest::Method::GET, &token, &api_path)
                        .await?
                }
                Err(err) => return Err(err),
            };
            Ok(list_keys_from_body(&body))
        }
    }

    fn read_kv_secret(
        &self,
        mount: &SecretPath,
        path: &SecretPath,
    ) -> impl std::future::Future<Output = Result<KvData, VaultError>> + Send {
        // Raw GET (not vaultrs typed reads): the metadata block of a KV2 response
        // carries fields Vault/OpenBao variants may emit as `null` or omit.
        // Rust's strict serde rejects `null` for `String` while Go's json decoder
        // tolerates it — parity requires the same leniency here.
        let url = format!("{}/v1/{}/data/{}", self.addr, mount.as_str(), path.as_str());
        let http = self.http.clone();
        let token = self.token.expose_secret().to_owned();
        async move {
            let body = Self::raw_json(http, &url, reqwest::Method::GET, &token, &url).await?;
            kv_data_from_value(body.get("data").unwrap_or(&Value::Null))
        }
    }

    fn write_kv_secret(
        &self,
        mount: &SecretPath,
        path: &SecretPath,
        data: &BTreeMap<String, String>,
    ) -> impl std::future::Future<Output = Result<(), VaultError>> + Send {
        async move {
            let endpoint = format!("{}/data/{}", mount.as_str(), path.as_str());
            Self::with_timeout(
                vaultrs::kv2::set(&self.inner, mount.as_str(), path.as_str(), data),
                &endpoint,
            )
            .await
            .map(|_| ())
        }
    }

    fn read_token_info(
        &self,
    ) -> impl std::future::Future<Output = Result<TokenInfo, VaultError>> + Send {
        async move {
            let response = Self::with_timeout(
                vaultrs::token::lookup_self(&self.inner),
                "auth/token/lookup-self",
            )
            .await?;
            Ok(TokenInfo {
                policies: response.policies,
                expire_time: response.expire_time,
            })
        }
    }

    fn sys_health(
        &self,
    ) -> impl std::future::Future<Output = Result<HealthInfo, VaultError>> + Send {
        // Raw GET instead of vaultrs::sys::health: OpenBao omits fields vaultrs
        // requires (e.g. `performance_standby`), so its strict parse fails there.
        let url = format!("{}/v1/sys/health", self.addr);
        let token = self.token.expose_secret().to_owned();
        let http = self.http.clone();
        async move {
            let response = tokio::time::timeout(
                REQUEST_TIMEOUT,
                http.get(&url).header("X-Vault-Token", token).send(),
            )
            .await
            .map_err(|_| VaultError::Connection("timed out".to_owned()))?
            .map_err(|err| VaultError::Connection(err.to_string()))?;
            let body: Value = response
                .json()
                .await
                .map_err(|err| VaultError::Parse(err.to_string()))?;
            Ok(HealthInfo {
                sealed: body.get("sealed").and_then(Value::as_bool).unwrap_or(false),
                version: body
                    .get("version")
                    .and_then(Value::as_str)
                    .unwrap_or(NA_VALUE)
                    .to_owned(),
            })
        }
    }

    fn capabilities_self(
        &self,
        paths: &[String],
    ) -> impl std::future::Future<Output = Result<BTreeMap<String, Vec<String>>, VaultError>> + Send
    {
        let url = format!("{}/v1/sys/capabilities-self", self.addr);
        let token = self.token.expose_secret().to_owned();
        let http = self.http.clone();
        let paths = paths.to_vec();
        async move {
            let request_body = serde_json::json!({ "paths": paths });
            let body =
                Self::raw_json_post(http, &url, &token, "sys/capabilities-self", &request_body)
                    .await?;
            let data = body
                .get("data")
                .and_then(Value::as_object)
                .ok_or_else(|| VaultError::Parse("capabilities response had no data".to_owned()))?;
            Ok(data
                .iter()
                .map(|(path, caps)| {
                    let list = caps.as_array().map_or_else(Vec::new, |caps| {
                        caps.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    });
                    (path.clone(), list)
                })
                .collect())
        }
    }

    fn delete_kv_secret_metadata(
        &self,
        mount: &SecretPath,
        path: &SecretPath,
    ) -> impl std::future::Future<Output = Result<(), VaultError>> + Send {
        let url = format!(
            "{}/v1/{}/metadata/{}",
            self.addr,
            mount.as_str(),
            path.as_str()
        );
        let api_path = format!("{}/metadata/{}", mount.as_str(), path.as_str());
        let token = self.token.expose_secret().to_owned();
        let http = self.http.clone();
        async move {
            Self::raw_json(http, &url, reqwest::Method::DELETE, &token, &api_path)
                .await
                .map(|_| ())
        }
    }

    fn list_acl_policies(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<PolicyEntry>, VaultError>> + Send {
        let url = format!("{}/v1/sys/policies/acl", self.addr);
        let api_path = "sys/policies/acl".to_owned();
        let http = self.http.clone();
        let token = self.token.expose_secret().to_owned();
        async move {
            let method = reqwest::Method::from_bytes(b"LIST")
                .map_err(|err| VaultError::Connection(err.to_string()))?;
            let body = match Self::raw_json(http.clone(), &url, method, &token, &api_path).await {
                Ok(body) => body,
                Err(VaultError::Api {
                    status: 400 | 403 | 405,
                    ..
                }) => {
                    let fallback_url = format!("{url}?list=true");
                    Self::raw_json(http, &fallback_url, reqwest::Method::GET, &token, &api_path)
                        .await?
                }
                Err(err) => return Err(err),
            };
            let mut entries: Vec<PolicyEntry> = body
                .get("data")
                .and_then(|data| data.get("keys"))
                .and_then(Value::as_array)
                .map_or_else(Vec::new, |keys| {
                    keys.iter()
                        .filter_map(Value::as_str)
                        .map(|name| PolicyEntry {
                            name: name.to_owned(),
                        })
                        .collect()
                });
            entries.sort_by(|left, right| left.name.cmp(&right.name));
            Ok(entries)
        }
    }

    fn read_acl_policy(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<PolicyDocument, VaultError>> + Send {
        let encoded_name = encode_acl_policy_name(name);
        let url = format!("{}/v1/sys/policies/acl/{encoded_name}", self.addr);
        let api_path = format!("sys/policies/acl/{encoded_name}");
        let requested_name = name.to_owned();
        let http = self.http.clone();
        let token = self.token.expose_secret().to_owned();
        async move {
            let body = Self::raw_json(http, &url, reqwest::Method::GET, &token, &api_path).await?;
            let data = body
                .get("data")
                .ok_or_else(|| VaultError::Parse("policy response had no data".to_owned()))?;
            let resolved_name = data
                .get("name")
                .and_then(Value::as_str)
                .map_or_else(|| requested_name.clone(), str::to_owned);
            let raw_policy = data
                .get("policy")
                .and_then(Value::as_str)
                .ok_or_else(|| VaultError::Parse("policy response had no policy".to_owned()))?;
            Ok(PolicyDocument {
                name: resolved_name,
                policy: decode_acl_policy_body(raw_policy)?,
            })
        }
    }

    fn write_acl_policy(
        &self,
        name: &str,
        policy: &str,
    ) -> impl std::future::Future<Output = Result<(), VaultError>> + Send {
        let encoded_name = encode_acl_policy_name(name);
        let url = format!("{}/v1/sys/policies/acl/{encoded_name}", self.addr);
        let api_path = format!("sys/policies/acl/{encoded_name}");
        let body = serde_json::json!({"policy": policy});
        let token = self.token.expose_secret().to_owned();
        let http = self.http.clone();
        async move {
            Self::raw_request(
                http.put(url).header("X-Vault-Token", token).json(&body),
                &api_path,
            )
            .await
            .map(|_| ())
        }
    }
}

fn secret_entry(key: &str) -> SecretEntry {
    if key.ends_with('/') {
        SecretEntry::dir(key)
    } else {
        SecretEntry::leaf(key)
    }
}

/// Extracts directory/leaf entries from the `data.keys` array of a list response.
fn list_keys_from_body(body: &Value) -> Vec<SecretEntry> {
    body.get("data")
        .and_then(|data| data.get("keys"))
        .and_then(Value::as_array)
        .map_or_else(Vec::new, |keys| {
            keys.iter()
                .filter_map(Value::as_str)
                .map(secret_entry)
                .collect()
        })
}

fn strip_trailing_slash(name: &str) -> &str {
    name.strip_suffix('/').map_or(name, |stripped| stripped)
}

fn kv_data_from_value(data_block: &Value) -> Result<KvData, VaultError> {
    let data_map = data_block
        .get("data")
        .and_then(Value::as_object)
        .ok_or_else(|| VaultError::Parse("KV2 data field was not an object".to_owned()))?;
    let data = data_map
        .iter()
        .map(|(key, value)| (key.clone(), SecretString::from(display_value(value))))
        .collect();
    let metadata = data_block.get("metadata").unwrap_or(&Value::Null);
    Ok(KvData {
        data,
        metadata: KvMetadata {
            version: metadata.get("version").and_then(Value::as_u64).unwrap_or(0),
            destroyed: metadata
                .get("destroyed")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            created_time: metadata
                .get("created_time")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        },
    })
}

fn display_value(value: &Value) -> String {
    match value {
        Value::String(raw) => raw.clone(),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::Array(_) | Value::Object(_) => {
            value.to_string()
        }
    }
}

fn map_client_error(err: ClientError, path: &str) -> VaultError {
    match err {
        ClientError::APIError { code, errors } => VaultError::Api {
            status: code,
            path: path.to_owned(),
            detail: truncate_detail(&errors.join("; ")),
        },
        ClientError::JsonParseError { source } => VaultError::Parse(source.to_string()),
        ClientError::ResponseEmptyError
        | ClientError::ResponseDataEmptyError
        | ClientError::ResponseWrapError
        | ClientError::InvalidUpdateParameter => VaultError::Parse(err.to_string()),
        ClientError::RestClientError { source } => VaultError::Connection(source.to_string()),
        ClientError::FileNotFoundError { path: file }
        | ClientError::FileReadError { path: file, .. }
        | ClientError::FileWriteError { path: file, .. }
        | ClientError::ParseCertificateError { path: file, .. } => {
            VaultError::Connection(format!("vault client file error at {file}"))
        }
        ClientError::InvalidLoginMethodError
        | ClientError::RestClientBuildError { .. }
        | ClientError::WrapInvalidError => VaultError::Connection(err.to_string()),
    }
}

fn truncate_detail(detail: &str) -> String {
    let mut output = String::new();
    for ch in detail.chars().take(ERROR_DETAIL_LIMIT) {
        output.push(ch);
    }
    output.replace(['\n', '\r'], " ")
}

/// Extracts the first `errors[0]` entry from a Vault error envelope.
fn error_detail_from_body(body: &Value) -> String {
    body.get("errors")
        .and_then(Value::as_array)
        .and_then(|errors| errors.first())
        .and_then(Value::as_str)
        .map_or_else(String::new, truncate_detail)
}

fn decode_acl_policy_body(policy: &str) -> Result<String, VaultError> {
    if let Some(payload) = policy.strip_prefix("base64:") {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .map_err(|err| VaultError::Parse(err.to_string()))?;
        String::from_utf8(bytes).map_err(|err| VaultError::Parse(err.to_string()))
    } else {
        Ok(policy.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_acl_policy_body, encode_acl_policy_name};

    #[test]
    fn decode_acl_policy_base64_prefix_decodes_utf8() {
        let decoded = decode_acl_policy_body("base64:cGF0aCBcInNlY3JldC9cIiB7fQ==")
            .expect("base64 policy should decode");
        assert_eq!(decoded, "path \\\"secret/\\\" {}");
    }

    #[test]
    fn encode_acl_policy_name_escapes_slashes() {
        let encoded = encode_acl_policy_name("team/admin");
        assert_eq!(encoded, "team%2Fadmin");
    }
}
