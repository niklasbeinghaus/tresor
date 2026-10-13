//! Application orchestration, input handling, background tasks, and root drawing.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::Value;
use tokio::sync::mpsc;

use crate::clipboard::{TextClipboard, default_clipboard};
use crate::config::Config;
use crate::constants::{NA_VALUE, STATUS_EXPIRY_SECS, keys};
use crate::editor::{EditBuffer, EditOutcome, EditorError};
use crate::model::{
    HealthInfo, KvData, MintedToken, SecretEntry, TokenCreateRequest, TokenInfo, WrappedToken,
};
use crate::path::SecretPath;
use crate::state::Mode;
use crate::store::{CacheKey, Msg, Store};
use crate::theme::Theme;
use crate::ui::command_line::{CommandLineModel, draw_command_line};
use crate::ui::commands::{Page, Permission, draw_commands};
use crate::ui::engines::{EnginesModel, draw_engines};
use crate::ui::header::{HeaderModel, StatusKind, StatusLine, draw_header};
use crate::ui::modal::{ModalField, ModalModel, draw_modal};
use crate::ui::policies::{PoliciesModel, PolicyPreview, draw_policies};
use crate::ui::prompt::{PromptKind, PromptModel, draw_prompt};
use crate::ui::secret_data::{DataMode, KeyRow, SecretDataModel, draw_secret_data};
use crate::ui::secrets::{SecretsModel, draw_secrets, sort_entries};
use crate::ui::token::{PaneModel, TokenViewModel, draw_token};
use crate::vault::{VaultApi, VaultError, encode_acl_policy_name};

const TASK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Synthetic name appended to a directory's data path when probing whether the
/// token may create a new secret there (so policy globs match like a real name).
const CAPABILITY_PROBE: &str = "__tresor_probe__";

/// Active single-field input prompt (new secret name / new key name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptState {
    /// What the prompt collects.
    pub kind: PromptKind,
    /// Current input text.
    pub input: String,
    /// Optional error (e.g. empty name, permission denied).
    pub error: Option<String>,
    /// Optional detail line shown in confirm prompts.
    pub detail: Option<String>,
}

/// Inline `:` command-line state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandLineState {
    /// Command text without leading `:`.
    pub input: String,
    /// Optional command parse/dispatch error.
    pub error: Option<String>,
}

/// Pending policy save payload between editor close and confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPolicySave {
    /// Policy name.
    pub name: String,
    /// Original policy text.
    pub old_policy: String,
    /// New policy text.
    pub new_policy: String,
}

/// Editor callback target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditorTarget {
    /// Edit an ACL policy document.
    Policy {
        /// Policy name.
        name: String,
        /// Policy text loaded before editor launch.
        original_policy: String,
    },
}

/// Editor request emitted by the app and consumed by the terminal owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditorRequest {
    /// Requested target.
    pub target: EditorTarget,
    /// Text buffer metadata.
    pub buffer: EditBuffer,
}

enum PolicyEffect {
    PoliciesLoaded,
    PolicyLoaded(String),
    PolicyWritten(String),
    PolicyCapabilities { name: String, writable: bool },
}

/// Header information loaded from Vault after connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderInfo {
    /// Vault server version.
    pub vault_version: String,
    /// Vault sealed state.
    pub sealed: Option<bool>,
    /// Comma-separated token policies.
    pub policies: String,
    /// Token expiry text.
    pub token_expiry: String,
}

impl Default for HeaderInfo {
    fn default() -> Self {
        Self {
            vault_version: NA_VALUE.to_owned(),
            sealed: None,
            policies: NA_VALUE.to_owned(),
            token_expiry: NA_VALUE.to_owned(),
        }
    }
}

/// Top-level application state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppState {
    /// Vault address/token modal is visible.
    ConfigInput,
    /// Main app mode is visible.
    Main(Mode),
}

/// Secret data view state owned by the app.
#[derive(Debug, Clone)]
pub struct SecretDataUi {
    /// Full leaf path inside the mounted engine.
    pub key: SecretPath,
    /// Loaded secret data.
    pub data: KvData,
    /// Selected key row.
    pub selected: usize,
    /// Current right-pane mode.
    pub mode: DataMode,
    /// Original values used for save change detection.
    pub original_data: BTreeMap<String, SecretString>,
}

/// Transient payload shown in the token inspector's preview pane.
#[derive(Debug, Clone)]
enum TokenPane {
    /// A freshly minted child token.
    Minted(MintedToken),
    /// A wrapping token.
    Wrapped(WrappedToken),
    /// A pretty-printed unwrapped payload.
    Unwrapped(String),
}

/// Child-token parameters accumulated across the chained input prompts.
#[derive(Debug, Clone, Default)]
struct ChildTokenDraft {
    /// Policies to attach to the child token.
    policies: Vec<String>,
    /// Optional TTL for the child token.
    ttl: Option<String>,
}

/// Running TUI application with injectable Vault API.
#[allow(
    clippy::struct_excessive_bools,
    reason = "capability flags are independent booleans read directly by the UI, not a state machine"
)]
pub struct App<V: VaultApi> {
    /// Current route state.
    pub state: AppState,
    /// Generation-tagged cache.
    pub store: Store,
    /// Vault API client.
    pub vault: Arc<V>,
    /// Runtime Vault configuration.
    pub config: Config,
    /// Semantic UI theme.
    pub theme: Theme,
    /// Version rendered in the header (pinned by tests; crate version by default).
    pub app_version: String,
    /// Transient header status line.
    pub status: Option<StatusLine>,
    /// Header health/token snapshot.
    pub info: Option<HeaderInfo>,
    pending: bool,
    /// Selected row in the engines view.
    pub engines_selected: usize,
    /// Selected row in the secrets view.
    pub secrets_selected: usize,
    /// Current directory inside the selected engine.
    pub secrets_path: SecretPath,
    /// Current engine mount.
    pub secrets_engine: SecretPath,
    /// Current secret data UI state.
    pub secret_data: Option<SecretDataUi>,
    /// Token may create/update secrets at the current context (permission gate).
    pub can_write: bool,
    /// Token may delete secrets at the current context (permission gate).
    pub can_delete: bool,
    /// Active input prompt, if any.
    pub prompt: Option<PromptState>,
    /// Full token details for the token inspector (`lookup_self`).
    pub token_details: Option<TokenInfo>,
    /// Mode to return to when leaving the token inspector.
    token_return: Mode,
    /// Transient payload shown in the token inspector pane.
    token_pane: Option<TokenPane>,
    /// Child-token parameters accumulated across the chained prompts.
    child_draft: Option<ChildTokenDraft>,
    /// Parsed wrap payload awaiting a TTL.
    wrap_payload: Option<Value>,
    /// Token may create child tokens (`auth/token/create`).
    pub token_can_create: bool,
    /// Token may wrap data (`sys/wrapping/wrap`).
    pub token_can_wrap: bool,
    /// Whether the token capability probe has resolved (gating fails closed until then).
    token_caps_loaded: bool,
    /// Active `:` command line, if any.
    pub command_line: Option<CommandLineState>,
    /// Selected row in the policies view.
    pub policies_selected: usize,
    /// Current selected policy write capability.
    pub policy_can_write: bool,
    pending_policy_edit: Option<String>,
    pending_policy_new: Option<String>,
    pending_policy_save: Option<PendingPolicySave>,
    policy_preview_error: Option<(String, String)>,
    /// Pending editor handoff request consumed by terminal owner.
    pub editor_request: Option<EditorRequest>,
    modal_addr: String,
    modal_token: String,
    modal_focus: ModalField,
    modal_error: Option<String>,
    status_at: Option<Instant>,
    tx: mpsc::UnboundedSender<Msg>,
    clipboard: Box<dyn TextClipboard>,
}

impl<V: VaultApi> std::fmt::Debug for App<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("App")
            .field("state", &self.state)
            .field("store", &self.store)
            .field("config", &self.config)
            .field("theme", &self.theme)
            .field("status", &self.status)
            .field("info", &self.info)
            .field("pending", &self.pending)
            .field("engines_selected", &self.engines_selected)
            .field("secrets_selected", &self.secrets_selected)
            .field("secrets_path", &self.secrets_path)
            .field("secrets_engine", &self.secrets_engine)
            .field("secret_data", &self.secret_data)
            .finish_non_exhaustive()
    }
}

impl<V: VaultApi + 'static> App<V> {
    /// Builds an app in main mode and returns its background message receiver.
    pub fn new(config: Config, vault: Arc<V>) -> (Self, mpsc::UnboundedReceiver<Msg>) {
        Self::build(
            AppState::Main(Mode::Engines),
            config,
            vault,
            Theme::default(),
        )
    }

    /// Builds an app with an explicit theme (e.g. loaded from a sofka config).
    pub fn new_with_theme(
        config: Config,
        vault: Arc<V>,
        theme: Theme,
    ) -> (Self, mpsc::UnboundedReceiver<Msg>) {
        Self::build(AppState::Main(Mode::Engines), config, vault, theme)
    }

    /// Builds an app that starts in the configuration modal.
    pub fn config_input(vault: Arc<V>) -> (Self, mpsc::UnboundedReceiver<Msg>) {
        Self::build(
            AppState::ConfigInput,
            Config::new("", ""),
            vault,
            Theme::default(),
        )
    }

    /// Builds a configuration-modal app with an explicit theme.
    pub fn config_input_with_theme(
        vault: Arc<V>,
        theme: Theme,
    ) -> (Self, mpsc::UnboundedReceiver<Msg>) {
        Self::build(AppState::ConfigInput, Config::new("", ""), vault, theme)
    }

    fn build(
        state: AppState,
        config: Config,
        vault: Arc<V>,
        theme: Theme,
    ) -> (Self, mpsc::UnboundedReceiver<Msg>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Self {
                state,
                store: Store::new(),
                vault,
                config,
                theme,
                app_version: env!("CARGO_PKG_VERSION").to_owned(),
                status: None,
                info: None,
                pending: false,
                engines_selected: 0,
                secrets_selected: 0,
                secrets_path: SecretPath::root(),
                secrets_engine: SecretPath::root(),
                secret_data: None,
                can_write: false,
                can_delete: false,
                prompt: None,
                token_details: None,
                token_return: Mode::Engines,
                token_pane: None,
                child_draft: None,
                wrap_payload: None,
                token_can_create: false,
                token_can_wrap: false,
                token_caps_loaded: false,
                command_line: None,
                policies_selected: 0,
                policy_can_write: false,
                pending_policy_edit: None,
                pending_policy_new: None,
                pending_policy_save: None,
                policy_preview_error: None,
                editor_request: None,
                modal_addr: String::new(),
                modal_token: String::new(),
                modal_focus: ModalField::Addr,
                modal_error: None,
                status_at: None,
                tx,
                clipboard: default_clipboard(),
            },
            rx,
        )
    }

    /// Replaces the clipboard adapter, primarily for tests.
    #[must_use]
    pub fn with_clipboard(mut self, clipboard: Box<dyn TextClipboard>) -> Self {
        self.clipboard = clipboard;
        self
    }

    /// Replaces the connection after modal submission and starts initial loads.
    pub fn connect_config(&mut self, config: Config, vault: Arc<V>) {
        self.config = config;
        self.vault = vault;
        self.state = AppState::Main(Mode::Engines);
        self.modal_error = None;
        self.spawn_initial_loads();
    }

    /// Returns the config typed into the modal.
    pub fn modal_config(&self) -> Config {
        Config::new(self.modal_addr.clone(), self.modal_token.clone())
    }

    /// Sets a modal error message.
    pub fn set_modal_error(&mut self, message: impl Into<String>) {
        self.modal_error = Some(message.into());
    }

    /// Spawns the initial header and engine loads.
    pub fn spawn_initial_loads(&mut self) {
        let generation = self.store.bump_generation();
        self.pending = true;
        self.spawn_read_engines(generation);
        self.spawn_read_health(generation);
        self.spawn_read_token(generation);
    }

    /// Spawns a message-producing task and sends its result to the app channel.
    pub fn spawn_msg(
        &self,
        tx: mpsc::UnboundedSender<Msg>,
        fut: impl Future<Output = Msg> + Send + 'static,
    ) {
        // Unit tests without a Tokio runtime reach spawning paths (e.g. the
        // capability probe from open_secret_data); skip so they stay hermetic.
        let Ok(_handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        tokio::spawn(async move {
            let msg = fut.await;
            if tx.send(msg).is_err() {
                tracing::debug!("app message receiver dropped");
            }
        });
    }

    /// Handles one terminal key event, returning true when the app should quit.
    pub fn handle_input(&mut self, key: KeyEvent) -> bool {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return true;
        }
        if self.prompt.is_some() {
            return self.handle_prompt_input(key);
        }
        if self.command_line.is_some() {
            return self.handle_command_line_input(key);
        }
        if matches!(self.state, AppState::Main(_))
            && key.code == KeyCode::Char(':')
            && !self.inside_secret_editor()
        {
            self.open_command_prompt();
            return false;
        }
        if key.code == KeyCode::Char(keys::COMMAND)
            && matches!(self.state, AppState::Main(_))
            && !self.inside_secret_editor()
        {
            self.command_line = Some(CommandLineState {
                input: String::new(),
                error: None,
            });
            return false;
        }
        match self.state {
            AppState::ConfigInput => self.handle_config_input(key),
            AppState::Main(Mode::Config) => false,
            AppState::Main(Mode::Engines) => self.handle_engines_input(key),
            AppState::Main(Mode::Secrets) => self.handle_secrets_input(key),
            AppState::Main(Mode::Policies) => self.handle_policies_input(key),
            AppState::Main(Mode::SecretData) => self.handle_secret_data_input(key),
            AppState::Main(Mode::Token) => self.handle_token_input(key),
        }
    }

    /// Folds a background message into app/store state.
    #[allow(
        clippy::too_many_lines,
        reason = "single fold point for all Msg variants by architecture"
    )]
    pub fn apply(&mut self, msg: Msg) {
        self.pending = false;
        if self.apply_token_event(&msg) {
            let _accepted = self.store.apply(msg);
            return;
        }
        match &msg {
            Msg::HealthLoaded { info, .. } => self.apply_health(info),
            Msg::TokenLoaded { info, .. } => self.apply_token(info),
            Msg::SecretLoaded { key, data, .. } => self.open_secret_data(key, data.clone()),
            Msg::SecretWritten { key, .. } => {
                self.set_status(StatusKind::Success, secret_updated_text(key.path.as_str()));
                self.spawn_load_secret(key.clone());
            }
            Msg::PathNotFound { key, .. } => {
                self.set_status(
                    StatusKind::Error,
                    format!("path '{}' does not exist", key.path.as_str()),
                );
                self.secrets_path = key.path.parent();
                self.state = AppState::Main(Mode::Secrets);
            }
            Msg::Failure { message, .. } => self.on_operation_failure(message),
            Msg::SecretCreated { key, .. } => {
                let name = key.path.child_name();
                self.set_status(
                    StatusKind::Success,
                    format!("secret '{}' created", name.as_str()),
                );
                self.spawn_load_secrets(self.current_secrets_key());
            }
            Msg::SecretDeleted { key, .. } => {
                let name = key.path.child_name();
                self.set_status(
                    StatusKind::Success,
                    format!("secret '{}' deleted", name.as_str()),
                );
                self.spawn_load_secrets(self.current_secrets_key());
            }
            Msg::Capabilities { .. }
            | Msg::EnginesLoaded { .. }
            | Msg::SecretsLoaded { .. }
            | Msg::HardRefreshed { .. }
            | Msg::TokenRenewed { .. }
            | Msg::TokenMinted { .. }
            | Msg::DataWrapped { .. }
            | Msg::DataUnwrapped { .. }
            | Msg::TokenCapabilities { .. }
            | Msg::PoliciesLoaded { .. }
            | Msg::PolicyLoaded { .. }
            | Msg::PolicyWritten { .. }
            | Msg::PolicyCapabilities { .. } => {}
        }

        let policy_effect = policy_effect(&msg);
        let mut cache_msg = msg;
        let capability_update = match &cache_msg {
            Msg::Capabilities {
                writable,
                deletable,
                ..
            } => Some((*writable, *deletable)),
            _ => None,
        };
        if let Msg::SecretsLoaded { entries, .. } = &mut cache_msg {
            sort_entries(entries);
        }
        let accepted = self.store.apply(cache_msg);
        if !accepted {
            return;
        }
        if let Some((writable, deletable)) = capability_update {
            self.can_write = writable;
            self.can_delete = deletable;
        }
        if let Some(effect) = policy_effect {
            self.apply_policy_effect(effect);
        }
    }

    // Applies the policy side effects of an accepted message. Runs after the store
    // fold so it acts on fresh state (`Msg::PoliciesLoaded` must populate the list
    // before its selected preview/capability loads are spawned), and a stale
    // message cannot open the editor or clear pending save state.
    fn apply_policy_effect(&mut self, effect: PolicyEffect) {
        match effect {
            PolicyEffect::PoliciesLoaded => {
                self.policy_can_write = false;
                self.policy_preview_error = None;
                self.pending_policy_edit = None;
                self.sync_policy_selection();
                self.spawn_selected_policy_load();
                self.spawn_selected_policy_capabilities();
            }
            PolicyEffect::PolicyLoaded(name) => {
                if self
                    .policy_preview_error
                    .as_ref()
                    .is_some_and(|(policy_name, _)| policy_name == &name)
                {
                    self.policy_preview_error = None;
                }
                let pending = self.pending_policy_edit.as_deref() == Some(name.as_str());
                let selected = self.selected_policy_name().as_deref() == Some(name.as_str());
                if pending && selected {
                    self.pending_policy_edit = None;
                    if let Some(policy) = self
                        .store
                        .policy_document(&name)
                        .map(|document| document.policy.clone())
                    {
                        self.editor_request = Some(EditorRequest {
                            target: EditorTarget::Policy {
                                name: name.clone(),
                                original_policy: policy.clone(),
                            },
                            buffer: EditBuffer {
                                initial_text: policy,
                                file_stem: name,
                                extension: ".hcl",
                            },
                        });
                    }
                }
            }
            PolicyEffect::PolicyWritten(name) => {
                self.pending_policy_save = None;
                self.set_status(StatusKind::Success, format!("policy '{name}' saved"));
                self.spawn_load_policies();
                self.spawn_load_policy(name);
            }
            PolicyEffect::PolicyCapabilities { name, writable } => {
                if self.selected_policy_name().as_deref() == Some(name.as_str()) {
                    self.policy_can_write = writable;
                }
                if self.pending_policy_new.as_deref() == Some(name.as_str()) {
                    let policy_name = name;
                    self.pending_policy_new = None;
                    if writable {
                        self.editor_request = Some(EditorRequest {
                            target: EditorTarget::Policy {
                                name: policy_name.clone(),
                                original_policy: String::new(),
                            },
                            buffer: EditBuffer {
                                initial_text: String::new(),
                                file_stem: policy_name,
                                extension: ".hcl",
                            },
                        });
                    } else {
                        self.set_status(StatusKind::Error, "no permission to edit policy");
                    }
                }
            }
        }
    }

    /// Applies token-inspector messages, returning true when one was handled.
    ///
    /// Token results and the capability probe are generation-checked here so a
    /// stale response can never overwrite newer UI state or reopen a gated action.
    fn apply_token_event(&mut self, msg: &Msg) -> bool {
        let current = self.store.generation();
        match msg {
            Msg::TokenRenewed { generation } => {
                if *generation == current {
                    self.set_status(StatusKind::Success, "token renewed");
                    self.spawn_read_token(current);
                }
            }
            Msg::TokenMinted { generation, minted } => {
                if *generation == current {
                    self.token_pane = Some(TokenPane::Minted(minted.clone()));
                    self.set_status(
                        StatusKind::Success,
                        "child token created - press c to copy it now",
                    );
                }
            }
            Msg::DataWrapped {
                generation,
                wrapped,
            } => {
                if *generation == current {
                    self.token_pane = Some(TokenPane::Wrapped(wrapped.clone()));
                    self.set_status(
                        StatusKind::Success,
                        "data wrapped - press c to copy the token now",
                    );
                }
            }
            Msg::DataUnwrapped {
                generation,
                payload,
            } => {
                if *generation == current {
                    self.token_pane = Some(TokenPane::Unwrapped(payload.clone()));
                    self.set_status(StatusKind::Success, "wrapping token unwrapped");
                }
            }
            Msg::TokenCapabilities {
                generation,
                can_create,
                can_wrap,
            } => {
                if *generation == current {
                    self.token_can_create = *can_create;
                    self.token_can_wrap = *can_wrap;
                    self.token_caps_loaded = true;
                }
            }
            _ => return false,
        }
        true
    }

    /// Handles a failed background operation. A failed secret read while the
    /// secret-data view is open backs out to the secrets browser and drops the
    /// now-dead entry from the parent listing (Go parity: `TogglePageAndRefresh`).
    fn on_operation_failure(&mut self, message: &str) {
        if self.state == AppState::Main(Mode::SecretData) {
            if let Some(secret) = &self.secret_data {
                let key = CacheKey {
                    mount: self.secrets_engine.clone(),
                    path: secret.key.clone(),
                };
                let generation = self.store.bump_generation();
                self.store.apply(Msg::PathNotFound { generation, key });
                self.secret_data = None;
                self.state = AppState::Main(Mode::Secrets);
            }
        }
        if self.state == AppState::Main(Mode::Policies)
            && let Some(name) = self.selected_policy_name()
        {
            self.policy_preview_error = Some((name, message.to_owned()));
        }
        self.set_status(StatusKind::Error, message);
    }

    /// Clears an expired transient status line.
    pub fn expire_status(&mut self) {
        let Some(status_at) = self.status_at else {
            return;
        };
        if status_at.elapsed().as_secs() >= STATUS_EXPIRY_SECS {
            self.status = None;
            self.status_at = None;
        }
    }

    /// Builds the pure header render model.
    pub fn header_model(&self) -> HeaderModel {
        let info = self.info.clone().unwrap_or_default();
        HeaderModel {
            app_version: self.app_version.clone(),
            vault_version: info.vault_version,
            addr: self.config.addr.clone(),
            sealed: info.sealed,
            policies: info.policies,
            token_expiry: info.token_expiry,
            status: self.status.clone(),
        }
    }

    /// Write/delete permission for the command bar and action gating.
    #[must_use]
    pub const fn permission(&self) -> Permission {
        Permission {
            write: self.can_write,
            delete: self.can_delete,
            create_token: self.token_can_create,
            wrap: self.token_can_wrap,
        }
    }

    /// The command-bar page for the current app state.
    pub const fn commands_page(&self) -> Page {
        match self.state {
            AppState::ConfigInput | AppState::Main(Mode::Config) => Page::Config,
            AppState::Main(Mode::Engines) => Page::Engines,
            AppState::Main(Mode::Secrets) => Page::Secrets,
            AppState::Main(Mode::Policies) => Page::Policies,
            AppState::Main(Mode::SecretData) => Page::SecretData,
            AppState::Main(Mode::Token) => Page::Token,
        }
    }

    /// Builds the pure engines render model.
    pub fn engines_model(&self) -> EnginesModel {
        EnginesModel {
            engines: self.store.engines().to_vec(),
            selected: self.engines_selected,
        }
    }

    /// Builds the pure secrets render model.
    pub fn secrets_model(&self) -> SecretsModel {
        let entries = self
            .store
            .secrets(&self.current_secrets_key())
            .map_or_else(Vec::new, <[SecretEntry]>::to_vec);
        SecretsModel {
            engine: self.secrets_engine.as_str().to_owned(),
            path: self.secrets_path.clone(),
            entries,
            selected: self.secrets_selected,
        }
    }

    /// Builds the pure secret data render model.
    pub fn secret_data_model(&self) -> Option<SecretDataModel> {
        let ui = self.secret_data.as_ref()?;
        let keys = ui
            .data
            .data
            .keys()
            .map(|key| KeyRow { label: key.clone() })
            .collect();
        Some(SecretDataModel {
            secret_name: ui.key.as_str().to_owned(),
            engine: self.secrets_engine.as_str().to_owned(),
            version: ui.data.metadata.version,
            created_time: ui.data.metadata.created_time.clone(),
            keys,
            selected: ui.selected,
            mode: ui.mode.clone(),
        })
    }

    /// Builds the pure policies render model.
    pub fn policies_model(&self) -> PoliciesModel {
        let entries = self.store.policies().to_vec();
        let preview = if entries.is_empty() {
            PolicyPreview::Empty
        } else if let Some(name) = self.selected_policy_name() {
            if let Some(document) = self.store.policy_document(&name) {
                PolicyPreview::Loaded {
                    name,
                    policy: document.policy.clone(),
                }
            } else if let Some((error_name, message)) = &self.policy_preview_error {
                if error_name == &name {
                    PolicyPreview::Error {
                        name,
                        message: message.clone(),
                    }
                } else {
                    PolicyPreview::Loading { name }
                }
            } else {
                PolicyPreview::Loading { name }
            }
        } else {
            PolicyPreview::Empty
        };
        PoliciesModel {
            entries,
            selected: self.policies_selected,
            preview,
        }
    }

    /// Builds the pure command-line render model.
    pub fn command_line_model(&self) -> Option<CommandLineModel> {
        self.command_line.as_ref().map(|state| CommandLineModel {
            input: state.input.clone(),
            error: state.error.clone(),
        })
    }

    /// Builds a pure modal render model.
    pub fn modal_model(&self, addr: String, token: String, focus: ModalField) -> ModalModel {
        ModalModel {
            addr,
            token,
            focus,
            error: self.modal_error.clone(),
        }
    }

    /// Builds the pure token inspector render model.
    pub fn token_model(&self) -> TokenViewModel {
        let details = self.token_details.clone().unwrap_or_default();
        TokenViewModel {
            loaded: self.token_details.is_some(),
            accessor: value_or_na(&details.accessor),
            display_name: value_or_na(&details.display_name),
            policies: if details.policies.is_empty() {
                NA_VALUE.to_owned()
            } else {
                details.policies.join(", ")
            },
            ttl: ttl_text(details.ttl),
            expire_time: details
                .expire_time
                .clone()
                .unwrap_or_else(|| "never".to_owned()),
            renewable: details.renewable,
            num_uses: uses_text(details.num_uses),
            orphan: details.orphan,
            pane: self.token_pane_model(),
        }
    }

    fn token_pane_model(&self) -> Option<PaneModel> {
        let pane = self.token_pane.as_ref()?;
        Some(match pane {
            TokenPane::Minted(minted) => PaneModel {
                title: "New Token (shown once)".to_owned(),
                warning: Some("copy now - this token is never shown again".to_owned()),
                body: minted.token.expose_secret().to_owned(),
            },
            TokenPane::Wrapped(wrapped) => PaneModel {
                title: "Wrapping Token (shown once)".to_owned(),
                warning: Some("copy now - this wrapping token is single-use".to_owned()),
                body: wrapped.token.expose_secret().to_owned(),
            },
            TokenPane::Unwrapped(payload) => PaneModel {
                title: "Unwrapped Payload".to_owned(),
                warning: None,
                body: payload.clone(),
            },
        })
    }

    /// Draws the complete app surface.
    pub fn draw(&self, frame: &mut Frame<'_>, area: Rect) {
        // Header needs 3 inner rows (wordmark, info, status) + borders; a shorter
        // area silently clips the status line. The command bar is one row below.
        let rows = Layout::vertical([
            Constraint::Length(5),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .split(area);
        let [header_area, commands_area, body_area] = rows.as_ref() else {
            return;
        };
        draw_header(frame, *header_area, &self.header_model(), &self.theme);
        if let Some(model) = self.command_line_model() {
            draw_command_line(frame, *commands_area, &model, &self.theme);
        } else {
            draw_commands(
                frame,
                *commands_area,
                self.commands_page(),
                self.permission(),
                &self.theme,
            );
        }
        match self.state {
            AppState::ConfigInput => draw_modal(
                frame,
                *body_area,
                &self.modal_model(
                    self.modal_addr.clone(),
                    self.modal_token.clone(),
                    self.modal_focus,
                ),
                &self.theme,
            ),
            AppState::Main(Mode::Config) => {}
            AppState::Main(Mode::Engines) => {
                draw_engines(frame, *body_area, &self.engines_model(), &self.theme);
            }
            AppState::Main(Mode::Secrets) => {
                draw_secrets(frame, *body_area, &self.secrets_model(), &self.theme);
            }
            AppState::Main(Mode::Policies) => {
                draw_policies(frame, *body_area, &self.policies_model(), &self.theme);
            }
            AppState::Main(Mode::SecretData) => {
                if let Some(model) = self.secret_data_model() {
                    draw_secret_data(frame, *body_area, &model, &self.theme);
                }
            }
            AppState::Main(Mode::Token) => {
                draw_token(frame, *body_area, &self.token_model(), &self.theme);
            }
        }
        if let Some(prompt) = &self.prompt {
            let model = PromptModel {
                kind: prompt.kind,
                input: prompt.input.clone(),
                error: prompt.error.clone(),
                detail: prompt.detail.clone(),
            };
            draw_prompt(frame, *body_area, &model, &self.theme);
        }
    }

    fn handle_config_input(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => true,
            KeyCode::Tab => {
                self.modal_focus = match self.modal_focus {
                    ModalField::Addr => ModalField::Token,
                    ModalField::Token => ModalField::Addr,
                };
                false
            }
            KeyCode::Enter => {
                self.config = self.modal_config();
                self.state = AppState::Main(Mode::Engines);
                self.spawn_initial_loads();
                false
            }
            KeyCode::Backspace => {
                match self.modal_focus {
                    ModalField::Addr => {
                        self.modal_addr.pop();
                    }
                    ModalField::Token => {
                        self.modal_token.pop();
                    }
                }
                false
            }
            KeyCode::Char(ch) => {
                match self.modal_focus {
                    ModalField::Addr => self.modal_addr.push(ch),
                    ModalField::Token => self.modal_token.push(ch),
                }
                false
            }
            KeyCode::BackTab
            | KeyCode::Left
            | KeyCode::Right
            | KeyCode::Up
            | KeyCode::Down
            | KeyCode::Home
            | KeyCode::End
            | KeyCode::PageUp
            | KeyCode::PageDown
            | KeyCode::Delete
            | KeyCode::Insert
            | KeyCode::F(_)
            | KeyCode::Null
            | KeyCode::CapsLock
            | KeyCode::ScrollLock
            | KeyCode::NumLock
            | KeyCode::PrintScreen
            | KeyCode::Pause
            | KeyCode::Menu
            | KeyCode::KeypadBegin
            | KeyCode::Media(_)
            | KeyCode::Modifier(_) => false,
        }
    }

    fn handle_engines_input(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => true,
            KeyCode::Up | KeyCode::Char('k') => {
                self.engines_selected = self.engines_selected.saturating_sub(1);
                false
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.engines_selected =
                    next_index(self.engines_selected, self.store.engines().len());
                false
            }
            KeyCode::Enter => {
                self.open_selected_engine();
                false
            }
            KeyCode::BackTab
            | KeyCode::Backspace
            | KeyCode::Left
            | KeyCode::Right
            | KeyCode::Home
            | KeyCode::End
            | KeyCode::PageUp
            | KeyCode::PageDown
            | KeyCode::Tab
            | KeyCode::Delete
            | KeyCode::Insert
            | KeyCode::F(_)
            | KeyCode::Char(_)
            | KeyCode::Null
            | KeyCode::CapsLock
            | KeyCode::ScrollLock
            | KeyCode::NumLock
            | KeyCode::PrintScreen
            | KeyCode::Pause
            | KeyCode::Menu
            | KeyCode::KeypadBegin
            | KeyCode::Media(_)
            | KeyCode::Modifier(_) => false,
        }
    }

    fn handle_secrets_input(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => {
                self.back_from_secrets();
                false
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.secrets_selected = self.secrets_selected.saturating_sub(1);
                false
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let len = self.secrets_model().entries.len();
                self.secrets_selected = next_index(self.secrets_selected, len);
                false
            }
            KeyCode::Enter => {
                self.open_selected_secret_entry();
                false
            }
            KeyCode::Char('n') => {
                self.open_new_secret_prompt();
                false
            }
            KeyCode::Char('d') => {
                self.open_delete_secret_prompt();
                false
            }
            KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.hard_refresh_current_path();
                false
            }
            KeyCode::BackTab
            | KeyCode::Backspace
            | KeyCode::Left
            | KeyCode::Right
            | KeyCode::Home
            | KeyCode::End
            | KeyCode::PageUp
            | KeyCode::PageDown
            | KeyCode::Tab
            | KeyCode::Delete
            | KeyCode::Insert
            | KeyCode::F(_)
            | KeyCode::Char(_)
            | KeyCode::Null
            | KeyCode::CapsLock
            | KeyCode::ScrollLock
            | KeyCode::NumLock
            | KeyCode::PrintScreen
            | KeyCode::Pause
            | KeyCode::Menu
            | KeyCode::KeypadBegin
            | KeyCode::Media(_)
            | KeyCode::Modifier(_) => false,
        }
    }

    fn handle_policies_input(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => {
                self.state = AppState::Main(Mode::Engines);
                false
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.policies_selected = self.policies_selected.saturating_sub(1);
                self.policy_can_write = false;
                self.policy_preview_error = None;
                self.pending_policy_edit = None;
                self.spawn_selected_policy_load();
                self.spawn_selected_policy_capabilities();
                false
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.policies_selected =
                    next_index(self.policies_selected, self.store.policies().len());
                self.policy_can_write = false;
                self.policy_preview_error = None;
                self.pending_policy_edit = None;
                self.spawn_selected_policy_load();
                self.spawn_selected_policy_capabilities();
                false
            }
            KeyCode::Enter => {
                self.spawn_selected_policy_load();
                false
            }
            KeyCode::Char('e') => {
                self.edit_selected_policy();
                false
            }
            KeyCode::Char('n') => {
                self.prompt = Some(PromptState {
                    kind: PromptKind::NewPolicy,
                    input: String::new(),
                    error: None,
                    detail: None,
                });
                false
            }
            _ => false,
        }
    }

    fn handle_secret_data_input(&mut self, key: KeyEvent) -> bool {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('s') {
            self.save_secret();
            return false;
        }
        match key.code {
            KeyCode::Esc => {
                self.state = AppState::Main(Mode::Secrets);
                false
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_secret_key_up();
                false
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                self.move_secret_key_down();
                false
            }
            KeyCode::Char(ch) if !self.inside_secret_editor() => match ch {
                keys::REVEAL => {
                    self.preview_selected_value();
                    false
                }
                keys::COPY => {
                    self.copy_selected_value();
                    false
                }
                keys::EDIT => {
                    self.edit_selected_value();
                    false
                }
                'a' => {
                    self.open_new_key_prompt();
                    false
                }
                _ => {
                    self.set_status(StatusKind::Info, "no action bound");
                    false
                }
            },
            // In the editor every other character is literal text — including
            // the letters used as lookup keys (x/e/c/a) outside the editor.
            KeyCode::Char(ch) => {
                self.edit_text(|text| text.push(ch));
                false
            }
            KeyCode::Backspace => {
                self.edit_text(|text| {
                    text.pop();
                });
                false
            }
            KeyCode::Enter => {
                self.edit_text(|text| text.push('\n'));
                false
            }
            KeyCode::BackTab
            | KeyCode::Left
            | KeyCode::Right
            | KeyCode::Home
            | KeyCode::End
            | KeyCode::PageUp
            | KeyCode::PageDown
            | KeyCode::Delete
            | KeyCode::Insert
            | KeyCode::F(_)
            | KeyCode::Null
            | KeyCode::CapsLock
            | KeyCode::ScrollLock
            | KeyCode::NumLock
            | KeyCode::PrintScreen
            | KeyCode::Pause
            | KeyCode::Menu
            | KeyCode::KeypadBegin
            | KeyCode::Media(_)
            | KeyCode::Modifier(_) => false,
        }
    }

    fn handle_token_input(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => self.leave_token_view(),
            KeyCode::Char('r') => self.spawn_renew_token(),
            KeyCode::Char('n') => self.open_child_token_prompt(),
            KeyCode::Char('w') => self.open_wrap_prompt(),
            KeyCode::Char('u') => self.open_unwrap_prompt(),
            KeyCode::Char('c') => self.copy_token_pane(),
            _ => {}
        }
        false
    }

    /// Leaves the token inspector, discarding any minted/wrapping token shown so
    /// it is never displayed again (the "shown once" contract).
    fn leave_token_view(&mut self) {
        self.token_pane = None;
        self.child_draft = None;
        self.wrap_payload = None;
        self.state = AppState::Main(self.token_return);
    }

    fn open_token_view(&mut self) {
        let current = match &self.state {
            AppState::Main(mode) => *mode,
            AppState::ConfigInput => Mode::Config,
        };
        if current != Mode::Token {
            self.token_return = current;
        }
        self.state = AppState::Main(Mode::Token);
        self.token_pane = None;
        self.child_draft = None;
        self.wrap_payload = None;
        self.token_can_create = false;
        self.token_can_wrap = false;
        self.token_caps_loaded = false;
        if self.token_details.is_none() {
            self.spawn_read_token(self.store.generation());
        }
        self.spawn_token_capabilities(self.store.generation());
    }

    fn open_command_prompt(&mut self) {
        self.command_line = Some(CommandLineState {
            input: String::new(),
            error: None,
        });
        self.prompt = Some(PromptState {
            kind: PromptKind::Command,
            input: String::new(),
            error: None,
            detail: None,
        });
    }

    fn open_child_token_prompt(&mut self) {
        if self.token_caps_loaded && !self.token_can_create {
            self.set_status(StatusKind::Error, "no permission to create child tokens");
            return;
        }
        self.child_draft = Some(ChildTokenDraft::default());
        self.next_prompt(PromptKind::ChildTokenPolicies);
    }

    fn open_wrap_prompt(&mut self) {
        if self.token_caps_loaded && !self.token_can_wrap {
            self.set_status(StatusKind::Error, "no permission to wrap data");
            return;
        }
        self.next_prompt(PromptKind::WrapPayload);
    }

    fn open_unwrap_prompt(&mut self) {
        self.next_prompt(PromptKind::UnwrapToken);
    }

    fn next_prompt(&mut self, kind: PromptKind) {
        self.prompt = Some(PromptState {
            kind,
            input: String::new(),
            error: None,
            detail: None,
        });
    }

    fn reopen_prompt(&mut self, kind: PromptKind, error: impl Into<String>) {
        let message = error.into();
        if kind == PromptKind::Command {
            self.command_line = Some(CommandLineState {
                input: String::new(),
                error: Some(message.clone()),
            });
        }
        self.prompt = Some(PromptState {
            kind,
            input: String::new(),
            error: Some(message),
            detail: None,
        });
    }

    fn run_command(&mut self, input: &str) {
        let command = input.split_whitespace().next().unwrap_or_default();
        match command {
            "policies" => {
                self.prompt = None;
                self.command_line = None;
                self.open_policies();
            }
            "token" | "t" => self.open_token_view(),
            "unwrap" | "u" => {
                self.open_token_view();
                self.open_unwrap_prompt();
            }
            "wrap" | "w" => {
                self.open_token_view();
                self.open_wrap_prompt();
            }
            other => {
                let message = if other.is_empty() {
                    "enter a command: token, unwrap, wrap, policies".to_owned()
                } else {
                    format!("unknown command: {other}")
                };
                self.reopen_prompt(PromptKind::Command, message);
            }
        }
    }

    fn advance_child_policies(&mut self, input: &str) {
        let policies = input
            .split([',', ' '])
            .filter(|policy| !policy.is_empty())
            .map(str::to_owned)
            .collect();
        self.child_draft = Some(ChildTokenDraft {
            policies,
            ttl: None,
        });
        self.next_prompt(PromptKind::ChildTokenTtl);
    }

    fn advance_child_ttl(&mut self, input: &str) {
        let ttl = if input.is_empty() {
            None
        } else {
            Some(input.to_owned())
        };
        if let Some(draft) = self.child_draft.as_mut() {
            draft.ttl = ttl;
        }
        self.next_prompt(PromptKind::ChildTokenUses);
    }

    fn finish_child_token(&mut self, input: &str) {
        if !self.token_can_create {
            self.set_status(StatusKind::Error, "no permission to create child tokens");
            return;
        }
        let num_uses = if input.is_empty() {
            None
        } else {
            let Ok(uses) = input.parse::<u64>() else {
                self.reopen_prompt(
                    PromptKind::ChildTokenUses,
                    "use limit must be a whole number",
                );
                return;
            };
            Some(uses)
        };
        let draft = self.child_draft.take().unwrap_or_default();
        self.spawn_create_token(TokenCreateRequest {
            policies: draft.policies,
            ttl: draft.ttl,
            num_uses,
        });
    }

    fn advance_wrap_payload(&mut self, input: &str) {
        match serde_json::from_str::<Value>(input) {
            Ok(payload) => {
                self.wrap_payload = Some(payload);
                self.next_prompt(PromptKind::WrapTtl);
            }
            Err(_) => self.reopen_prompt(PromptKind::WrapPayload, "payload must be valid JSON"),
        }
    }

    fn finish_wrap(&mut self, input: &str) {
        if !self.token_can_wrap {
            self.set_status(StatusKind::Error, "no permission to wrap data");
            return;
        }
        let ttl = if input.is_empty() {
            None
        } else {
            Some(input.to_owned())
        };
        let payload = self.wrap_payload.take().unwrap_or(Value::Null);
        self.spawn_wrap(payload, ttl);
    }

    fn copy_token_pane(&mut self) {
        let Some(pane) = self.token_pane_model() else {
            self.set_status(StatusKind::Info, "nothing to copy");
            return;
        };
        match self.clipboard.copy(&pane.body) {
            Ok(()) => self.set_status(StatusKind::Success, "Copied to clipboard"),
            Err(err) => self.set_status(StatusKind::Error, err.to_string()),
        }
    }

    fn spawn_renew_token(&mut self) {
        let generation = self.store.bump_generation();
        self.pending = true;
        let vault = Arc::clone(&self.vault);
        self.spawn_msg(self.tx.clone(), async move {
            timed(generation, vault.renew_token_self(), |()| {
                Msg::TokenRenewed { generation }
            })
            .await
        });
    }

    fn spawn_create_token(&mut self, request: TokenCreateRequest) {
        let generation = self.store.bump_generation();
        self.pending = true;
        let vault = Arc::clone(&self.vault);
        self.spawn_msg(self.tx.clone(), async move {
            timed(generation, vault.create_token(&request), |minted| {
                Msg::TokenMinted { generation, minted }
            })
            .await
        });
    }

    fn spawn_wrap(&mut self, payload: Value, ttl: Option<String>) {
        let generation = self.store.bump_generation();
        self.pending = true;
        let vault = Arc::clone(&self.vault);
        self.spawn_msg(self.tx.clone(), async move {
            timed(
                generation,
                vault.wrap_data(&payload, ttl.as_deref()),
                |wrapped| Msg::DataWrapped {
                    generation,
                    wrapped,
                },
            )
            .await
        });
    }

    fn spawn_unwrap(&mut self, wrapping_token: &str) {
        let generation = self.store.bump_generation();
        self.pending = true;
        let vault = Arc::clone(&self.vault);
        let wrapping_token = wrapping_token.to_owned();
        self.spawn_msg(self.tx.clone(), async move {
            timed(generation, vault.unwrap_data(&wrapping_token), |payload| {
                Msg::DataUnwrapped {
                    generation,
                    payload,
                }
            })
            .await
        });
    }

    fn spawn_token_capabilities(&self, generation: u64) {
        let paths = vec![
            "auth/token/create".to_owned(),
            "sys/wrapping/wrap".to_owned(),
        ];
        let vault = Arc::clone(&self.vault);
        self.spawn_msg(self.tx.clone(), async move {
            let (can_create, can_wrap) =
                match tokio::time::timeout(TASK_TIMEOUT, vault.capabilities_self(&paths)).await {
                    Ok(Ok(caps)) => (
                        caps_allow(&caps, "auth/token/create"),
                        caps_allow(&caps, "sys/wrapping/wrap"),
                    ),
                    _ => (false, false),
                };
            Msg::TokenCapabilities {
                generation,
                can_create,
                can_wrap,
            }
        });
    }

    fn open_selected_engine(&mut self) {
        let Some(entry) = self.store.engines().get(self.engines_selected) else {
            return;
        };
        self.secrets_engine = entry.name.clone();
        self.secrets_path = SecretPath::root();
        self.secrets_selected = 0;
        self.state = AppState::Main(Mode::Secrets);
        let key = self.current_secrets_key();
        if self.store.secrets(&key).is_none() {
            self.spawn_load_secrets(key);
        }
    }

    fn open_selected_secret_entry(&mut self) {
        let entries = self.secrets_model().entries;
        let Some(entry) = entries.get(self.secrets_selected) else {
            return;
        };
        let next_path = self.secrets_path.join(&entry.name);
        if entry.is_dir {
            self.secrets_path = next_path;
            self.secrets_selected = 0;
            let key = self.current_secrets_key();
            if self.store.secrets(&key).is_none() {
                self.spawn_load_secrets(key);
            }
        } else {
            let key = CacheKey {
                mount: self.secrets_engine.clone(),
                path: next_path,
            };
            self.state = AppState::Main(Mode::SecretData);
            self.spawn_load_secret(key);
        }
    }

    fn back_from_secrets(&mut self) {
        if self.secrets_path.is_root() {
            self.state = AppState::Main(Mode::Engines);
        } else {
            self.secrets_path = self.secrets_path.parent();
            self.secrets_selected = 0;
        }
    }

    fn hard_refresh_current_path(&mut self) {
        let key = self.current_secrets_key();
        let generation = self.store.bump_generation();
        let _accepted = self.store.apply(Msg::HardRefreshed {
            generation,
            key: key.clone(),
        });
        self.spawn_load_secrets_with_generation(key, generation);
    }

    fn open_secret_data(&mut self, key: &CacheKey, data: KvData) {
        let original_data = data.data.clone();
        self.secret_data = Some(SecretDataUi {
            key: key.path.clone(),
            data,
            selected: 0,
            mode: DataMode::ListOnly,
            original_data,
        });
        self.state = AppState::Main(Mode::SecretData);
        let mount = self.secrets_engine.clone();
        let path = key.path.clone();
        self.spawn_capabilities(self.store.generation(), &mount, &path, true);
    }

    fn current_secrets_key(&self) -> CacheKey {
        CacheKey {
            mount: self.secrets_engine.clone(),
            path: self.secrets_path.clone(),
        }
    }

    fn selected_data_key(&self) -> Option<String> {
        let ui = self.secret_data.as_ref()?;
        ui.data.data.keys().nth(ui.selected).cloned()
    }

    fn selected_data_value(&self) -> Option<String> {
        let key = self.selected_data_key()?;
        let ui = self.secret_data.as_ref()?;
        ui.data
            .data
            .get(&key)
            .map(|value| value.expose_secret().to_owned())
    }

    fn preview_selected_value(&mut self) {
        let Some(key) = self.selected_data_key() else {
            return;
        };
        let Some(value) = self.selected_data_value() else {
            return;
        };
        if let Some(ui) = self.secret_data.as_mut() {
            ui.mode = DataMode::Preview { key, value };
        }
    }

    fn copy_selected_value(&mut self) {
        let Some(value) = self.selected_data_value() else {
            return;
        };
        match self.clipboard.copy(&value) {
            Ok(()) => self.set_status(StatusKind::Success, "Copied to clipboard"),
            Err(err) => self.set_status(StatusKind::Error, err.to_string()),
        }
    }

    fn edit_selected_value(&mut self) {
        let Some(key) = self.selected_data_key() else {
            return;
        };
        let Some(value) = self.selected_data_value() else {
            return;
        };
        if let Some(ui) = self.secret_data.as_mut() {
            ui.mode = DataMode::Edit { key, text: value };
        }
    }

    fn edit_text(&mut self, edit: impl FnOnce(&mut String)) {
        let Some(ui) = self.secret_data.as_mut() else {
            return;
        };
        if let DataMode::Edit { text, .. } = &mut ui.mode {
            edit(text);
        }
    }

    fn move_secret_key_up(&mut self) {
        let Some(ui) = self.secret_data.as_mut() else {
            return;
        };
        ui.selected = ui.selected.saturating_sub(1);
        self.reopen_edit_for_selected_key();
    }

    fn move_secret_key_down(&mut self) {
        let Some(len) = self.secret_data.as_ref().map(|ui| ui.data.data.len()) else {
            return;
        };
        if let Some(ui) = self.secret_data.as_mut() {
            ui.selected = next_index(ui.selected, len);
        }
        self.reopen_edit_for_selected_key();
    }

    fn reopen_edit_for_selected_key(&mut self) {
        let editing = self
            .secret_data
            .as_ref()
            .is_some_and(|ui| matches!(ui.mode, DataMode::Edit { .. }));
        if editing {
            self.edit_selected_value();
        }
    }

    fn save_secret(&mut self) {
        let Some(ui) = self.secret_data.as_ref() else {
            return;
        };
        let DataMode::Edit { key, text } = &ui.mode else {
            self.set_status(StatusKind::Info, "Nothing to save...");
            return;
        };
        let Some(original) = ui.original_data.get(key) else {
            self.set_status(StatusKind::Error, format!("key '{key}' does not exist"));
            return;
        };
        if original.expose_secret() == text {
            self.set_status(StatusKind::Info, "Nothing to save...");
            return;
        }
        let mut data = BTreeMap::new();
        for (data_key, value) in &ui.original_data {
            let output = if data_key == key {
                text.clone()
            } else {
                value.expose_secret().to_owned()
            };
            data.insert(data_key.clone(), output);
        }
        let cache_key = CacheKey {
            mount: self.secrets_engine.clone(),
            path: ui.key.clone(),
        };
        self.spawn_write_secret(cache_key, data);
    }

    fn apply_health(&mut self, health: &HealthInfo) {
        let mut info = self.info.clone().unwrap_or_default();
        info.vault_version.clone_from(&health.version);
        info.sealed = Some(health.sealed);
        self.info = Some(info);
    }

    fn apply_token(&mut self, token: &TokenInfo) {
        self.token_details = Some(token.clone());
        let mut info = self.info.clone().unwrap_or_default();
        info.policies = if token.policies.is_empty() {
            NA_VALUE.to_owned()
        } else {
            token.policies.join(", ")
        };
        info.token_expiry = if token.is_eternal() {
            "eternal".to_owned()
        } else {
            token
                .expire_time
                .clone()
                .unwrap_or_else(|| NA_VALUE.to_owned())
        };
        self.info = Some(info);
    }

    fn set_status(&mut self, kind: StatusKind, msg: impl Into<String>) {
        self.status = Some(StatusLine {
            kind,
            text: msg.into(),
        });
        self.status_at = Some(Instant::now());
    }

    fn spawn_read_engines(&self, generation: u64) {
        let vault = Arc::clone(&self.vault);
        self.spawn_msg(self.tx.clone(), async move {
            timed(generation, vault.read_secret_engines(), |entries| {
                Msg::EnginesLoaded {
                    generation,
                    entries,
                }
            })
            .await
        });
    }

    fn spawn_read_health(&self, generation: u64) {
        let vault = Arc::clone(&self.vault);
        self.spawn_msg(self.tx.clone(), async move {
            timed(generation, vault.sys_health(), |info| Msg::HealthLoaded {
                generation,
                info,
            })
            .await
        });
    }

    fn spawn_read_token(&self, generation: u64) {
        let vault = Arc::clone(&self.vault);
        self.spawn_msg(self.tx.clone(), async move {
            timed(generation, vault.read_token_info(), |info| {
                Msg::TokenLoaded { generation, info }
            })
            .await
        });
    }

    fn spawn_load_secrets(&mut self, key: CacheKey) {
        let generation = self.store.bump_generation();
        self.spawn_load_secrets_with_generation(key, generation);
    }

    /// Probes the token's write capability for a KV2 data path and folds the
    /// result back as [`Msg::Capabilities`] (shares the caller's generation).
    ///
    /// `leaf` probes an existing secret's data path; otherwise a synthetic
    /// name under the directory is probed so policy globs are evaluated like a
    /// real new secret would be.
    fn spawn_capabilities(
        &self,
        generation: u64,
        mount: &SecretPath,
        path: &SecretPath,
        leaf: bool,
    ) {
        let probe = if leaf {
            format!("{}/data/{}", mount.as_str(), path.as_str())
        } else {
            format!("{mount}/data/{path}{CAPABILITY_PROBE}")
        };
        let vault = Arc::clone(&self.vault);
        self.spawn_msg(self.tx.clone(), async move {
            let (writable, deletable) = match tokio::time::timeout(
                TASK_TIMEOUT,
                vault.capabilities_self(std::slice::from_ref(&probe)),
            )
            .await
            {
                Ok(Ok(caps)) => caps.get(&probe).map_or((false, false), |list| {
                    let has = |cap: &str| list.iter().any(|entry| entry == cap);
                    // `root` is the literal capability of the root token.
                    let root = has("root");
                    (
                        root || has("create") || has("update"),
                        root || has("delete"),
                    )
                }),
                _ => (false, false),
            };
            Msg::Capabilities {
                generation,
                writable,
                deletable,
            }
        });
    }

    fn spawn_load_secrets_with_generation(&mut self, key: CacheKey, generation: u64) {
        self.pending = true;
        let probe_mount = key.mount.clone();
        let probe_path = key.path.clone();
        let vault = Arc::clone(&self.vault);
        self.spawn_msg(self.tx.clone(), async move {
            match tokio::time::timeout(TASK_TIMEOUT, vault.list_kv_secrets(&key.mount, &key.path))
                .await
            {
                Ok(Ok(entries)) => Msg::SecretsLoaded {
                    generation,
                    key,
                    entries,
                },
                Ok(Err(err)) if err.status() == Some(404) => Msg::PathNotFound { generation, key },
                Ok(Err(err)) => Msg::Failure {
                    generation,
                    message: err.message(),
                },
                Err(_elapsed) => timeout_msg(generation),
            }
        });
        self.spawn_capabilities(generation, &probe_mount, &probe_path, false);
    }

    fn spawn_load_secret(&mut self, key: CacheKey) {
        let generation = self.store.bump_generation();
        self.pending = true;
        let vault = Arc::clone(&self.vault);
        self.spawn_msg(self.tx.clone(), async move {
            match tokio::time::timeout(TASK_TIMEOUT, vault.read_kv_secret(&key.mount, &key.path))
                .await
            {
                Ok(Ok(data)) => Msg::SecretLoaded {
                    generation,
                    key,
                    data,
                },
                Ok(Err(err)) if err.status() == Some(404) => Msg::Failure {
                    generation,
                    message: format!(
                        "secret '{}' does not exist: {}",
                        key.path.as_str(),
                        err.message()
                    ),
                },
                Ok(Err(err)) => Msg::Failure {
                    generation,
                    message: err.message(),
                },
                Err(_elapsed) => timeout_msg(generation),
            }
        });
    }

    fn spawn_load_policies(&mut self) {
        let generation = self.store.bump_generation();
        self.pending = true;
        let vault = Arc::clone(&self.vault);
        self.spawn_msg(self.tx.clone(), async move {
            match tokio::time::timeout(TASK_TIMEOUT, vault.list_acl_policies()).await {
                Ok(Ok(entries)) => Msg::PoliciesLoaded {
                    generation,
                    entries,
                },
                Ok(Err(err)) => Msg::Failure {
                    generation,
                    message: err.message(),
                },
                Err(_elapsed) => timeout_msg(generation),
            }
        });
    }

    fn spawn_load_policy(&mut self, name: String) {
        // Shares the caller's generation: a policy load and the capability probe
        // spawned in the same navigation step must not supersede each other, or
        // the load result is dropped as stale (mirrors the KV capability rule).
        let generation = self.store.generation();
        self.pending = true;
        let vault = Arc::clone(&self.vault);
        self.spawn_msg(self.tx.clone(), async move {
            match tokio::time::timeout(TASK_TIMEOUT, vault.read_acl_policy(&name)).await {
                Ok(Ok(document)) => Msg::PolicyLoaded {
                    generation,
                    name,
                    document,
                },
                Ok(Err(err)) => Msg::Failure {
                    generation,
                    message: err.message(),
                },
                Err(_elapsed) => timeout_msg(generation),
            }
        });
    }

    fn spawn_write_policy(&mut self, name: String, policy: String) {
        let generation = self.store.bump_generation();
        self.pending = true;
        let vault = Arc::clone(&self.vault);
        self.spawn_msg(self.tx.clone(), async move {
            match tokio::time::timeout(TASK_TIMEOUT, vault.write_acl_policy(&name, &policy)).await {
                Ok(Ok(())) => Msg::PolicyWritten { generation, name },
                Ok(Err(err)) => Msg::Failure {
                    generation,
                    message: err.message(),
                },
                Err(_elapsed) => timeout_msg(generation),
            }
        });
    }

    fn spawn_policy_capabilities(&self, name: String) {
        // Shares the caller's generation (see `spawn_load_policy`).
        let generation = self.store.generation();
        let path = format!("sys/policies/acl/{}", encode_acl_policy_name(&name));
        let vault = Arc::clone(&self.vault);
        self.spawn_msg(self.tx.clone(), async move {
            let writable = match tokio::time::timeout(
                TASK_TIMEOUT,
                vault.capabilities_self(std::slice::from_ref(&path)),
            )
            .await
            {
                Ok(Ok(caps)) => caps.get(&path).is_some_and(|list| {
                    let has = |cap: &str| list.iter().any(|entry| entry == cap);
                    has("root") || has("create") || has("update")
                }),
                _ => false,
            };
            Msg::PolicyCapabilities {
                generation,
                name,
                writable,
            }
        });
    }

    fn open_new_secret_prompt(&mut self) {
        if !self.can_write {
            self.set_status(StatusKind::Error, "no permission to create secrets here");
            return;
        }
        self.prompt = Some(PromptState {
            kind: PromptKind::NewSecret,
            input: String::new(),
            error: None,
            detail: None,
        });
    }

    fn inside_secret_editor(&self) -> bool {
        matches!(
            self.secret_data.as_ref().map(|ui| &ui.mode),
            Some(DataMode::Edit { .. })
        )
    }

    fn open_delete_secret_prompt(&mut self) {
        if !self.can_delete {
            self.set_status(StatusKind::Error, "no permission to delete secrets here");
            return;
        }
        let entries = self.secrets_model().entries;
        let Some(entry) = entries.get(self.secrets_selected) else {
            return;
        };
        if entry.is_dir {
            self.set_status(
                StatusKind::Info,
                "directories are virtual — delete the secrets inside them",
            );
            return;
        }
        self.prompt = Some(PromptState {
            kind: PromptKind::DeleteSecret,
            input: entry.name.as_str().to_owned(),
            error: None,
            detail: None,
        });
    }

    fn spawn_delete_secret(&mut self, key: CacheKey) {
        let generation = self.store.bump_generation();
        self.pending = true;
        let vault = Arc::clone(&self.vault);
        self.spawn_msg(self.tx.clone(), async move {
            match tokio::time::timeout(
                TASK_TIMEOUT,
                vault.delete_kv_secret_metadata(&key.mount, &key.path),
            )
            .await
            {
                Ok(Ok(())) => Msg::SecretDeleted { generation, key },
                Ok(Err(err)) => Msg::Failure {
                    generation,
                    message: format!(
                        "could not delete '{}': {}",
                        key.path.as_str(),
                        err.message()
                    ),
                },
                Err(_elapsed) => timeout_msg(generation),
            }
        });
    }

    fn open_new_key_prompt(&mut self) {
        if !self.can_write {
            self.set_status(StatusKind::Error, "no permission to add keys here");
            return;
        }
        self.prompt = Some(PromptState {
            kind: PromptKind::NewKey,
            input: String::new(),
            error: None,
            detail: None,
        });
    }

    #[must_use]
    fn handle_prompt_input(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => {
                if self
                    .prompt
                    .as_ref()
                    .is_some_and(|prompt| prompt.kind == PromptKind::SavePolicy)
                {
                    self.pending_policy_save = None;
                    self.set_status(StatusKind::Info, "policy save cancelled");
                }
                self.prompt = None;
                self.command_line = None;
                self.child_draft = None;
                self.wrap_payload = None;
            }
            KeyCode::Enter => self.submit_prompt(),
            KeyCode::Backspace => {
                if let Some(prompt) = self.prompt.as_mut() {
                    prompt.input.pop();
                    if prompt.kind == PromptKind::Command {
                        if let Some(command_line) = self.command_line.as_mut() {
                            command_line.input.pop();
                        }
                    }
                }
            }
            KeyCode::Char(ch) => {
                if let Some(prompt) = self.prompt.as_mut() {
                    if !matches!(
                        prompt.kind,
                        PromptKind::DeleteSecret | PromptKind::SavePolicy
                    ) {
                        prompt.input.push(ch);
                        if prompt.kind == PromptKind::Command {
                            if let Some(command_line) = self.command_line.as_mut() {
                                command_line.input.push(ch);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        false
    }

    fn submit_prompt(&mut self) {
        let Some(mut prompt) = self.prompt.take() else {
            return;
        };
        if prompt.kind == PromptKind::SavePolicy {
            let name = prompt.input.trim().to_owned();
            if name.is_empty() {
                prompt.error = Some("name cannot be empty".to_owned());
                self.prompt = Some(prompt);
                return;
            }
            self.save_policy(&name);
            return;
        }
        let input = prompt.input.trim().to_owned();
        if prompt.kind.requires_input() && input.is_empty() {
            prompt.error = Some(empty_prompt_message(prompt.kind).to_owned());
            self.prompt = Some(prompt);
            return;
        }
        match prompt.kind {
            PromptKind::Command => {
                self.command_line = Some(CommandLineState {
                    input: input.clone(),
                    error: None,
                });
                self.run_command(&input);
            }
            PromptKind::NewSecret => self.create_secret(&input),
            PromptKind::NewKey => self.add_key(&input),
            PromptKind::DeleteSecret => self.delete_secret(&input),
            PromptKind::ChildTokenPolicies => self.advance_child_policies(&input),
            PromptKind::ChildTokenTtl => self.advance_child_ttl(&input),
            PromptKind::ChildTokenUses => self.finish_child_token(&input),
            PromptKind::WrapPayload => self.advance_wrap_payload(&input),
            PromptKind::WrapTtl => self.finish_wrap(&input),
            PromptKind::UnwrapToken => self.spawn_unwrap(&input),
            PromptKind::NewPolicy => self.create_policy(&input),
            PromptKind::SavePolicy => unreachable!("handled above"),
        }
    }

    fn delete_secret(&mut self, name: &str) {
        let key = CacheKey {
            mount: self.secrets_engine.clone(),
            path: self.secrets_path.join(&SecretPath::new(name)),
        };
        self.spawn_delete_secret(key);
    }

    fn create_secret(&mut self, name: &str) {
        let path = self.secrets_path.join(&SecretPath::new(name));
        let key = CacheKey {
            mount: self.secrets_engine.clone(),
            path,
        };
        self.spawn_create_secret(key);
    }

    fn add_key(&mut self, name: &str) {
        let Some(ui) = self.secret_data.as_mut() else {
            return;
        };
        if ui.data.data.contains_key(name) {
            self.prompt = Some(PromptState {
                kind: PromptKind::NewKey,
                input: name.to_owned(),
                error: Some("key already exists".to_owned()),
                detail: None,
            });
            return;
        }
        ui.data.data.insert(name.to_owned(), SecretString::from(""));
        ui.original_data
            .insert(name.to_owned(), SecretString::from(""));
        ui.mode = DataMode::Edit {
            key: name.to_owned(),
            text: String::new(),
        };
        ui.selected = ui.data.data.keys().position(|key| key == name).unwrap_or(0);
        self.set_status(
            StatusKind::Info,
            format!("key '{name}' added - type a value and Ctrl+S to save"),
        );
    }

    fn create_policy(&mut self, name: &str) {
        if let Err(message) = validate_policy_name(name) {
            self.prompt = Some(PromptState {
                kind: PromptKind::NewPolicy,
                input: name.to_owned(),
                error: Some(message),
                detail: None,
            });
            return;
        }
        self.pending_policy_new = Some(name.to_owned());
        self.spawn_policy_capabilities(name.to_owned());
    }

    fn save_policy(&mut self, name: &str) {
        let Some(pending) = &self.pending_policy_save else {
            return;
        };
        if pending.name != name {
            return;
        }
        self.spawn_write_policy(pending.name.clone(), pending.new_policy.clone());
    }

    fn spawn_create_secret(&mut self, key: CacheKey) {
        let generation = self.store.bump_generation();
        self.pending = true;
        let vault = Arc::clone(&self.vault);
        let empty = BTreeMap::new();
        self.spawn_msg(self.tx.clone(), async move {
            match tokio::time::timeout(
                TASK_TIMEOUT,
                vault.write_kv_secret(&key.mount, &key.path, &empty),
            )
            .await
            {
                Ok(Ok(())) => Msg::SecretCreated { generation, key },
                Ok(Err(err)) => Msg::Failure {
                    generation,
                    message: format!(
                        "could not create '{}': {}",
                        key.path.as_str(),
                        err.message()
                    ),
                },
                Err(_elapsed) => timeout_msg(generation),
            }
        });
    }

    fn spawn_write_secret(&mut self, key: CacheKey, data: BTreeMap<String, String>) {
        let generation = self.store.bump_generation();
        self.pending = true;
        let vault = Arc::clone(&self.vault);
        self.spawn_msg(self.tx.clone(), async move {
            match tokio::time::timeout(
                TASK_TIMEOUT,
                vault.write_kv_secret(&key.mount, &key.path, &data),
            )
            .await
            {
                Ok(Ok(())) => Msg::SecretWritten { generation, key },
                Ok(Err(err)) => Msg::Failure {
                    generation,
                    message: err.message(),
                },
                Err(_elapsed) => timeout_msg(generation),
            }
        });
    }

    fn handle_command_line_input(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => self.command_line = None,
            KeyCode::Backspace => {
                if let Some(command_line) = self.command_line.as_mut() {
                    command_line.input.pop();
                }
            }
            KeyCode::Enter => self.submit_command_line(),
            KeyCode::Char(ch) => {
                if let Some(command_line) = self.command_line.as_mut() {
                    command_line.input.push(ch);
                }
            }
            _ => {}
        }
        false
    }

    fn submit_command_line(&mut self) {
        let Some(input) = self.command_line.as_ref().map(|state| state.input.clone()) else {
            return;
        };
        let other = input.trim().to_owned();
        if other.is_empty() {
            self.command_line = None;
            self.prompt = None;
            return;
        }
        if other == "policies" {
            self.open_policies();
            return;
        }
        self.command_line = Some(CommandLineState {
            input: input.clone(),
            error: Some(format!("unknown command: {other}")),
        });
        self.prompt = Some(PromptState {
            kind: PromptKind::Command,
            input,
            error: Some(format!("unknown command: {other}")),
            detail: None,
        });
    }

    fn open_policies(&mut self) {
        self.command_line = None;
        self.state = AppState::Main(Mode::Policies);
        self.policies_selected = 0;
        self.policy_can_write = false;
        self.pending_policy_edit = None;
        if self.store.policies().is_empty() {
            self.spawn_load_policies();
        } else {
            self.sync_policy_selection();
            self.spawn_selected_policy_load();
            self.spawn_selected_policy_capabilities();
        }
    }

    fn sync_policy_selection(&mut self) {
        let len = self.store.policies().len();
        if len == 0 {
            self.policies_selected = 0;
            return;
        }
        self.policies_selected = self.policies_selected.min(len - 1);
    }

    fn selected_policy_name(&self) -> Option<String> {
        self.store
            .policies()
            .get(self.policies_selected)
            .map(|entry| entry.name.clone())
    }

    fn spawn_selected_policy_load(&mut self) {
        if let Some(name) = self.selected_policy_name() {
            if self.store.policy_document(&name).is_none() {
                self.spawn_load_policy(name);
            }
        }
    }

    fn spawn_selected_policy_capabilities(&self) {
        if let Some(name) = self.selected_policy_name() {
            self.spawn_policy_capabilities(name);
        }
    }

    fn edit_selected_policy(&mut self) {
        let Some(name) = self.selected_policy_name() else {
            return;
        };
        if !self.policy_can_write {
            self.set_status(StatusKind::Error, "no permission to edit policy");
            return;
        }
        if let Some(document) = self.store.policy_document(&name) {
            self.editor_request = Some(EditorRequest {
                target: EditorTarget::Policy {
                    name: name.clone(),
                    original_policy: document.policy.clone(),
                },
                buffer: EditBuffer {
                    initial_text: document.policy.clone(),
                    file_stem: name,
                    extension: ".hcl",
                },
            });
            return;
        }
        self.pending_policy_edit = Some(name.clone());
        self.set_status(
            StatusKind::Info,
            format!("loading policy '{name}' before editing"),
        );
        self.spawn_load_policy(name);
    }

    /// Takes the next pending editor request.
    #[allow(
        clippy::missing_const_for_fn,
        reason = "const qualification is not important for this mutable state accessor"
    )]
    pub fn take_editor_request(&mut self) -> Option<EditorRequest> {
        self.editor_request.take()
    }

    /// Completes an editor request and updates UI state from the edit outcome.
    pub fn complete_editor_request(
        &mut self,
        request: EditorRequest,
        result: Result<EditOutcome, EditorError>,
    ) {
        match result {
            Err(error) => self.set_status(StatusKind::Error, error.to_string()),
            Ok(EditOutcome::Unchanged) => self.set_status(StatusKind::Info, "No changes to save"),
            Ok(EditOutcome::Changed(text)) => match request.target {
                EditorTarget::Policy {
                    name,
                    original_policy,
                } => {
                    let detail = format_policy_save_detail(&original_policy, &text);
                    self.pending_policy_save = Some(PendingPolicySave {
                        name: name.clone(),
                        old_policy: original_policy,
                        new_policy: text,
                    });
                    self.prompt = Some(PromptState {
                        kind: PromptKind::SavePolicy,
                        input: name,
                        error: None,
                        detail: Some(detail),
                    });
                }
            },
        }
    }
}

async fn timed<T>(
    generation: u64,
    future: impl Future<Output = Result<T, VaultError>>,
    success: impl FnOnce(T) -> Msg,
) -> Msg {
    match tokio::time::timeout(TASK_TIMEOUT, future).await {
        Ok(Ok(value)) => success(value),
        Ok(Err(err)) => Msg::Failure {
            generation,
            message: err.message(),
        },
        Err(_elapsed) => timeout_msg(generation),
    }
}

fn policy_effect(msg: &Msg) -> Option<PolicyEffect> {
    match msg {
        Msg::PoliciesLoaded { .. } => Some(PolicyEffect::PoliciesLoaded),
        Msg::PolicyLoaded { name, .. } => Some(PolicyEffect::PolicyLoaded(name.clone())),
        Msg::PolicyWritten { name, .. } => Some(PolicyEffect::PolicyWritten(name.clone())),
        Msg::PolicyCapabilities { name, writable, .. } => Some(PolicyEffect::PolicyCapabilities {
            name: name.clone(),
            writable: *writable,
        }),
        _ => None,
    }
}

fn validate_policy_name(name: &str) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err("name cannot be empty".to_owned());
    }
    if name.contains('/') {
        return Err("name must not contain '/'".to_owned());
    }
    if name.contains('\n') || name.contains('\r') {
        return Err("name must not contain newlines".to_owned());
    }
    Ok(())
}

fn format_policy_save_detail(old_policy: &str, new_policy: &str) -> String {
    format!(
        "{} bytes / {} lines → {} bytes / {} lines",
        old_policy.len(),
        line_count(old_policy),
        new_policy.len(),
        line_count(new_policy)
    )
}

fn line_count(text: &str) -> usize {
    if text.is_empty() {
        0
    } else {
        text.lines().count()
    }
}

fn timeout_msg(generation: u64) -> Msg {
    Msg::Failure {
        generation,
        message: VaultError::Connection("timed out".to_owned()).message(),
    }
}

fn next_index(current: usize, len: usize) -> usize {
    len.checked_sub(1)
        .map_or(0, |last| current.saturating_add(1).min(last))
}

fn secret_updated_text(path: &str) -> String {
    format!("Secret '{path}' updated successfully")
}

const fn empty_prompt_message(kind: PromptKind) -> &'static str {
    match kind {
        PromptKind::NewSecret | PromptKind::NewKey => "name cannot be empty",
        _ => "input cannot be empty",
    }
}

fn value_or_na(value: &str) -> String {
    if value.is_empty() {
        NA_VALUE.to_owned()
    } else {
        value.to_owned()
    }
}

fn ttl_text(seconds: u64) -> String {
    if seconds == 0 {
        return "none".to_owned();
    }
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;
    format!("{hours}h {minutes}m {secs}s")
}

fn uses_text(uses: u64) -> String {
    if uses == 0 {
        "unlimited".to_owned()
    } else {
        uses.to_string()
    }
}

fn caps_allow(caps: &BTreeMap<String, Vec<String>>, path: &str) -> bool {
    caps.get(path).is_some_and(|list| {
        list.iter()
            .any(|cap| matches!(cap.as_str(), "create" | "update" | "root"))
    })
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests use direct assertions and snapshot helpers"
)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;
    use crate::clipboard::ClipboardError;
    use crate::model::{KvMetadata, PolicyDocument, PolicyEntry};
    use crate::vault::VaultApi;

    #[derive(Debug)]
    struct FakeVault {
        engines: Vec<SecretEntry>,
        policies: Vec<PolicyEntry>,
        listings: Mutex<HashMap<(SecretPath, SecretPath), Vec<SecretEntry>>>,
        data: Mutex<HashMap<(SecretPath, SecretPath), KvData>>,
        policy_documents: Mutex<HashMap<String, PolicyDocument>>,
        policy_writes: Mutex<Vec<(String, String)>>,
        writes: Mutex<Vec<WriteRecord>>,
        deletes: Mutex<Vec<(SecretPath, SecretPath)>>,
        writable_all: bool,
    }

    type WriteRecord = (SecretPath, SecretPath, BTreeMap<String, String>);

    impl Default for FakeVault {
        fn default() -> Self {
            Self {
                engines: Vec::new(),
                policies: Vec::new(),
                listings: Mutex::new(HashMap::new()),
                data: Mutex::new(HashMap::new()),
                policy_documents: Mutex::new(HashMap::new()),
                policy_writes: Mutex::new(Vec::new()),
                writes: Mutex::new(Vec::new()),
                deletes: Mutex::new(Vec::new()),
                writable_all: true,
            }
        }
    }

    impl FakeVault {
        fn seeded() -> Arc<Self> {
            let vault = Arc::new(Self {
                engines: vec![SecretEntry::leaf("secret")],
                policies: vec![
                    PolicyEntry {
                        name: "default".to_owned(),
                    },
                    PolicyEntry {
                        name: "team".to_owned(),
                    },
                ],
                ..Self::default()
            });
            vault.insert_listing(
                SecretPath::new("secret"),
                SecretPath::root(),
                vec![SecretEntry::dir("team/"), SecretEntry::leaf("root")],
            );
            vault.insert_listing(
                SecretPath::new("secret"),
                SecretPath::new("team/"),
                vec![SecretEntry::leaf("api")],
            );
            vault.insert_data(
                SecretPath::new("secret"),
                SecretPath::new("team/api"),
                kv_data("old"),
            );
            vault
                .policy_documents
                .lock()
                .expect("policy documents lock")
                .insert(
                    "team".to_owned(),
                    PolicyDocument {
                        name: "team".to_owned(),
                        policy: "path \"secret/data/team/*\" { capabilities = [\"read\"] }"
                            .to_owned(),
                    },
                );
            vault
        }

        fn insert_listing(&self, mount: SecretPath, path: SecretPath, entries: Vec<SecretEntry>) {
            self.listings
                .lock()
                .expect("listings lock")
                .insert((mount, path), entries);
        }

        fn insert_data(&self, mount: SecretPath, path: SecretPath, data: KvData) {
            self.data
                .lock()
                .expect("data lock")
                .insert((mount, path), data);
        }

        fn writes(&self) -> Vec<WriteRecord> {
            self.writes.lock().expect("writes lock").clone()
        }

        fn policy_writes(&self) -> Vec<(String, String)> {
            self.policy_writes
                .lock()
                .expect("policy writes lock")
                .clone()
        }
    }

    #[allow(
        clippy::manual_async_fn,
        reason = "VaultApi futures must be Send for tokio::spawn; async fn cannot express that contract here"
    )]
    impl VaultApi for FakeVault {
        fn read_secret_engines(
            &self,
        ) -> impl Future<Output = Result<Vec<SecretEntry>, VaultError>> + Send {
            async move { Ok(self.engines.clone()) }
        }

        fn list_kv_secrets(
            &self,
            mount: &SecretPath,
            path: &SecretPath,
        ) -> impl Future<Output = Result<Vec<SecretEntry>, VaultError>> + Send {
            async move {
                self.listings
                    .lock()
                    .expect("listings lock")
                    .get(&(mount.clone(), path.clone()))
                    .cloned()
                    .ok_or_else(|| VaultError::Api {
                        status: 404,
                        path: path.as_str().to_owned(),
                        detail: "missing".to_owned(),
                    })
            }
        }

        fn read_kv_secret(
            &self,
            mount: &SecretPath,
            path: &SecretPath,
        ) -> impl Future<Output = Result<KvData, VaultError>> + Send {
            async move {
                self.data
                    .lock()
                    .expect("data lock")
                    .get(&(mount.clone(), path.clone()))
                    .cloned()
                    .ok_or_else(|| VaultError::Api {
                        status: 404,
                        path: path.as_str().to_owned(),
                        detail: "missing".to_owned(),
                    })
            }
        }

        fn write_kv_secret(
            &self,
            mount: &SecretPath,
            path: &SecretPath,
            data: &BTreeMap<String, String>,
        ) -> impl Future<Output = Result<(), VaultError>> + Send {
            async move {
                self.writes.lock().expect("writes lock").push((
                    mount.clone(),
                    path.clone(),
                    data.clone(),
                ));
                let password = data.get("password").map_or("", String::as_str);
                self.insert_data(mount.clone(), path.clone(), kv_data(password));
                Ok(())
            }
        }

        fn delete_kv_secret_metadata(
            &self,
            mount: &SecretPath,
            path: &SecretPath,
        ) -> impl Future<Output = Result<(), VaultError>> + Send {
            async move {
                self.deletes
                    .lock()
                    .expect("deletes lock")
                    .push((mount.clone(), path.clone()));
                self.listings
                    .lock()
                    .expect("listings lock")
                    .entry((mount.clone(), path.parent()))
                    .or_default()
                    .retain(|entry| entry.name != path.child_name());
                Ok(())
            }
        }

        fn read_token_info(&self) -> impl Future<Output = Result<TokenInfo, VaultError>> + Send {
            async move {
                Ok(TokenInfo {
                    policies: vec!["root".to_owned()],
                    expire_time: None,
                    ..TokenInfo::default()
                })
            }
        }

        fn sys_health(&self) -> impl Future<Output = Result<HealthInfo, VaultError>> + Send {
            async move {
                Ok(HealthInfo {
                    sealed: false,
                    version: "1.18.0".to_owned(),
                })
            }
        }

        fn capabilities_self(
            &self,
            paths: &[String],
        ) -> impl Future<Output = Result<BTreeMap<String, Vec<String>>, VaultError>> + Send
        {
            let writable = self.writable_all;
            let paths = paths.to_vec();
            async move {
                Ok(paths
                    .into_iter()
                    .map(|path| {
                        let caps = if writable {
                            vec![
                                "create".to_owned(),
                                "update".to_owned(),
                                "delete".to_owned(),
                                "read".to_owned(),
                            ]
                        } else {
                            Vec::new()
                        };
                        (path, caps)
                    })
                    .collect())
            }
        }

        fn renew_token_self(&self) -> impl Future<Output = Result<(), VaultError>> + Send {
            async move { Ok(()) }
        }

        fn create_token(
            &self,
            request: &TokenCreateRequest,
        ) -> impl Future<Output = Result<MintedToken, VaultError>> + Send {
            let policies = request.policies.clone();
            async move {
                Ok(MintedToken {
                    token: SecretString::from("child-token-value"),
                    accessor: "child-accessor".to_owned(),
                    policies,
                    ttl: None,
                    renewable: false,
                })
            }
        }

        fn wrap_data(
            &self,
            _data: &Value,
            _ttl: Option<&str>,
        ) -> impl Future<Output = Result<WrappedToken, VaultError>> + Send {
            async move {
                Ok(WrappedToken {
                    token: SecretString::from("wrapping-token-value"),
                    accessor: "wrap-accessor".to_owned(),
                    ttl: 300,
                })
            }
        }

        fn unwrap_data(
            &self,
            _wrapping_token: &str,
        ) -> impl Future<Output = Result<String, VaultError>> + Send {
            async move { Ok("{\n  \"password\": \"hunter2\"\n}".to_owned()) }
        }

        fn list_acl_policies(
            &self,
        ) -> impl Future<Output = Result<Vec<PolicyEntry>, VaultError>> + Send {
            async move { Ok(self.policies.clone()) }
        }

        fn read_acl_policy(
            &self,
            name: &str,
        ) -> impl Future<Output = Result<PolicyDocument, VaultError>> + Send {
            let key = name.to_owned();
            async move {
                self.policy_documents
                    .lock()
                    .expect("policy documents lock")
                    .get(&key)
                    .cloned()
                    .ok_or_else(|| VaultError::Api {
                        status: 404,
                        path: format!("sys/policies/acl/{key}"),
                        detail: "missing".to_owned(),
                    })
            }
        }

        fn write_acl_policy(
            &self,
            name: &str,
            policy: &str,
        ) -> impl Future<Output = Result<(), VaultError>> + Send {
            let name = name.to_owned();
            let policy = policy.to_owned();
            async move {
                self.policy_writes
                    .lock()
                    .expect("policy writes lock")
                    .push((name.clone(), policy.clone()));
                self.policy_documents
                    .lock()
                    .expect("policy documents lock")
                    .insert(name.clone(), PolicyDocument { name, policy });
                Ok(())
            }
        }
    }

    #[derive(Debug, Default)]
    struct TestClipboard {
        copied: Mutex<Vec<String>>,
    }

    impl TextClipboard for TestClipboard {
        fn copy(&self, text: &str) -> Result<(), ClipboardError> {
            self.copied
                .lock()
                .expect("clipboard lock")
                .push(text.to_owned());
            Ok(())
        }
    }

    fn kv_data(password: &str) -> KvData {
        KvData {
            data: BTreeMap::from([
                (
                    "password".to_owned(),
                    SecretString::from(password.to_owned()),
                ),
                (
                    "username".to_owned(),
                    SecretString::from("alice".to_owned()),
                ),
            ]),
            metadata: KvMetadata {
                version: 1,
                destroyed: false,
                created_time: "2026-10-13T10:00:00Z".to_owned(),
            },
        }
    }

    fn test_app() -> (App<FakeVault>, mpsc::UnboundedReceiver<Msg>, Arc<FakeVault>) {
        let vault = FakeVault::seeded();
        let (app, rx) = App::new(Config::new("http://vault", "token"), Arc::clone(&vault));
        (
            app.with_clipboard(Box::<TestClipboard>::default()),
            rx,
            vault,
        )
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ctrl(ch: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(ch), KeyModifiers::CONTROL)
    }

    #[test]
    fn connect_flow_when_messages_arrive_populates_models() {
        let (mut app, _rx, _vault) = test_app();
        let generation = app.store.bump_generation();

        app.apply(Msg::EnginesLoaded {
            generation,
            entries: vec![SecretEntry::leaf("secret")],
        });
        app.apply(Msg::HealthLoaded {
            generation,
            info: HealthInfo {
                sealed: false,
                version: "1.18.0".to_owned(),
            },
        });

        assert_eq!(
            app.engines_model().engines,
            vec![SecretEntry::leaf("secret")]
        );
        assert_eq!(app.header_model().vault_version, "1.18.0");
        assert_eq!(app.header_model().sealed, Some(false));
    }

    #[tokio::test]
    async fn engines_enter_when_engine_selected_opens_secrets() {
        let (mut app, _rx, _vault) = test_app();
        let generation = app.store.bump_generation();
        app.apply(Msg::EnginesLoaded {
            generation,
            entries: vec![SecretEntry::leaf("secret")],
        });

        let quit = app.handle_input(key(KeyCode::Enter));

        assert!(!quit);
        assert_eq!(app.state, AppState::Main(Mode::Secrets));
        assert_eq!(app.secrets_engine, SecretPath::new("secret"));
    }

    #[tokio::test]
    async fn secrets_enter_when_dir_then_leaf_drills_and_opens_data() {
        let (mut app, _rx, _vault) = test_app();
        let generation = app.store.bump_generation();
        app.apply(Msg::EnginesLoaded {
            generation,
            entries: vec![SecretEntry::leaf("secret")],
        });
        app.handle_input(key(KeyCode::Enter));
        let listing_generation = app.store.bump_generation();
        app.apply(Msg::SecretsLoaded {
            generation: listing_generation,
            key: CacheKey {
                mount: SecretPath::new("secret"),
                path: SecretPath::root(),
            },
            entries: vec![SecretEntry::dir("team/")],
        });

        app.handle_input(key(KeyCode::Enter));
        assert_eq!(app.secrets_path, SecretPath::new("team/"));
        let secret_generation = app.store.bump_generation();
        app.apply(Msg::SecretLoaded {
            generation: secret_generation,
            key: CacheKey {
                mount: SecretPath::new("secret"),
                path: SecretPath::new("team/api"),
            },
            data: kv_data("old"),
        });

        assert_eq!(app.state, AppState::Main(Mode::SecretData));
        assert!(app.secret_data_model().is_some());
    }

    #[test]
    fn escape_navigates_secret_data_to_secrets_to_engines() {
        let (mut app, _rx, _vault) = test_app();
        app.state = AppState::Main(Mode::SecretData);
        app.secrets_path = SecretPath::root();

        app.handle_input(key(KeyCode::Esc));
        assert_eq!(app.state, AppState::Main(Mode::Secrets));

        app.handle_input(key(KeyCode::Esc));
        assert_eq!(app.state, AppState::Main(Mode::Engines));
    }

    #[test]
    fn hard_refresh_404_backs_out_to_parent_and_evicts_cache() {
        let (mut app, _rx, _vault) = test_app();
        let generation = app.store.bump_generation();
        let parent = CacheKey {
            mount: SecretPath::new("secret"),
            path: SecretPath::new("team/"),
        };
        let child = CacheKey {
            mount: SecretPath::new("secret"),
            path: SecretPath::new("team/deleted/"),
        };
        app.apply(Msg::SecretsLoaded {
            generation,
            key: parent.clone(),
            entries: vec![SecretEntry::dir("deleted/"), SecretEntry::leaf("kept")],
        });
        app.secrets_path = child.path.clone();

        app.apply(Msg::PathNotFound {
            generation,
            key: child.clone(),
        });

        assert_eq!(app.secrets_path, parent.path);
        assert_eq!(app.store.secrets(&child), None);
        assert_eq!(
            app.store.secrets(&parent),
            Some([SecretEntry::leaf("kept")].as_slice())
        );
    }

    #[tokio::test]
    async fn save_when_unchanged_reports_noop_and_changed_writes() {
        let (mut app, mut rx, vault) = test_app();
        app.secrets_engine = SecretPath::new("secret");
        app.open_secret_data(
            &CacheKey {
                mount: SecretPath::new("secret"),
                path: SecretPath::new("team/api"),
            },
            kv_data("old"),
        );
        app.edit_selected_value();

        app.handle_input(ctrl('s'));
        assert_eq!(
            app.status.as_ref().map(|status| status.text.as_str()),
            Some("Nothing to save...")
        );

        app.edit_text(|text| *text = "new".to_owned());
        app.handle_input(ctrl('s'));
        // The write message may be preceded by the capability probe result.
        for _ in 0..4 {
            let msg = rx.recv().await.expect("message");
            app.apply(msg);
            if app
                .status
                .as_ref()
                .is_some_and(|status| status.text == "Secret 'team/api' updated successfully")
            {
                break;
            }
        }

        assert_eq!(vault.writes().len(), 1);
        assert_eq!(
            app.status.as_ref().map(|status| status.text.as_str()),
            Some("Secret 'team/api' updated successfully")
        );
    }

    #[test]
    fn copy_selected_value_uses_injected_clipboard() {
        let clipboard = Box::<TestClipboard>::default();
        let (mut app, _rx, _vault) = test_app();
        app.clipboard = clipboard;
        app.open_secret_data(
            &CacheKey {
                mount: SecretPath::new("secret"),
                path: SecretPath::new("team/api"),
            },
            kv_data("old"),
        );

        app.handle_input(key(KeyCode::Char('c')));

        assert_eq!(
            app.status.as_ref().map(|status| status.text.as_str()),
            Some("Copied to clipboard")
        );
    }

    #[test]
    fn draw_composes_header_and_engines() {
        let (mut app, _rx, _vault) = test_app();
        // Pin the version so release bumps never invalidate this snapshot.
        app.app_version = "0.1.0".to_owned();
        let generation = app.store.bump_generation();
        app.apply(Msg::EnginesLoaded {
            generation,
            entries: vec![SecretEntry::leaf("secret"), SecretEntry::leaf("kv")],
        });
        let backend = TestBackend::new(80, 14);
        let mut terminal = Terminal::new(backend).expect("terminal");

        terminal
            .draw(|frame| app.draw(frame, frame.area()))
            .expect("draw");
        let buffer = terminal.backend().buffer();
        let mut actual = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                actual.push_str(
                    buffer
                        .cell((x, y))
                        .map_or("", ratatui::buffer::Cell::symbol),
                );
            }
            actual.push('\n');
        }

        insta::assert_snapshot!(actual);
    }

    #[test]
    fn new_secret_prompt_gated_by_permission_when_read_only() {
        // Given: a read-only token in the secrets view.
        let (mut app, _rx, _vault) = test_app();
        app.state = AppState::Main(Mode::Secrets);
        app.can_write = false;

        // When: `n` is pressed.
        app.handle_input(key(KeyCode::Char('n')));

        // Then: no prompt opens and a permission error is shown.
        assert_eq!(app.prompt, None);
        assert_eq!(app.status.as_ref().map(|s| s.kind), Some(StatusKind::Error));
    }

    #[test]
    fn command_line_switches_to_policies() {
        let (mut app, _rx, _vault) = test_app();
        app.handle_input(key(KeyCode::Char(':')));
        for ch in "policies".chars() {
            app.handle_input(key(KeyCode::Char(ch)));
        }
        app.handle_input(key(KeyCode::Enter));
        assert_eq!(app.state, AppState::Main(Mode::Policies));
        assert!(app.command_line.is_none());
    }

    #[test]
    fn command_line_unknown_sets_error() {
        let (mut app, _rx, _vault) = test_app();
        app.handle_input(key(KeyCode::Char(':')));
        app.handle_input(key(KeyCode::Char('x')));
        app.handle_input(key(KeyCode::Enter));
        assert_eq!(
            app.command_line
                .as_ref()
                .and_then(|state| state.error.clone()),
            Some("unknown command: x".to_owned())
        );
    }

    #[test]
    fn colon_in_config_modal_is_typed_not_a_command() {
        let (mut app, _rx, _vault) = test_app();
        app.state = AppState::ConfigInput;

        app.handle_input(key(KeyCode::Char(':')));

        assert!(app.command_line.is_none());
        assert_eq!(app.modal_addr, ":");
    }

    #[test]
    fn policies_model_shows_entries() {
        let (mut app, _rx, _vault) = test_app();
        let generation = app.store.bump_generation();
        app.apply(Msg::PoliciesLoaded {
            generation,
            entries: vec![PolicyEntry {
                name: "default".to_owned(),
            }],
        });
        let model = app.policies_model();
        assert_eq!(model.entries.len(), 1);
    }

    #[test]
    fn policies_enter_triggers_loading_preview_when_missing_cache() {
        let (mut app, _rx, _vault) = test_app();
        app.state = AppState::Main(Mode::Policies);
        let generation = app.store.bump_generation();
        app.apply(Msg::PoliciesLoaded {
            generation,
            entries: vec![PolicyEntry {
                name: "team".to_owned(),
            }],
        });
        app.handle_input(key(KeyCode::Enter));
        let model = app.policies_model();
        assert!(matches!(model.preview, PolicyPreview::Loading { .. }));
    }

    #[test]
    fn policy_navigation_shares_generation_so_loads_are_not_dropped() {
        let (mut app, _rx, _vault) = test_app();
        app.state = AppState::Main(Mode::Policies);
        let generation = app.store.bump_generation();
        app.apply(Msg::PoliciesLoaded {
            generation,
            entries: vec![
                PolicyEntry {
                    name: "alpha".to_owned(),
                },
                PolicyEntry {
                    name: "beta".to_owned(),
                },
            ],
        });
        let before = app.store.generation();

        // When: navigation moves the selection (spawns a load + capability probe).
        app.handle_input(key(KeyCode::Char('j')));

        // Then: the load/probe rode the current generation instead of bumping, so
        // the load result is accepted rather than dropped as stale.
        assert_eq!(app.store.generation(), before);
        app.apply(Msg::PolicyLoaded {
            generation: before,
            name: "beta".to_owned(),
            document: PolicyDocument {
                name: "beta".to_owned(),
                policy: "path \"secret/*\" {}".to_owned(),
            },
        });
        assert!(app.store.policy_document("beta").is_some());
    }

    #[tokio::test]
    async fn policies_loaded_spawns_selected_preview_load() {
        let vault = Arc::new(FakeVault {
            policies: vec![PolicyEntry {
                name: "team".to_owned(),
            }],
            ..FakeVault::default()
        });
        vault
            .policy_documents
            .lock()
            .expect("policy documents lock")
            .insert(
                "team".to_owned(),
                PolicyDocument {
                    name: "team".to_owned(),
                    policy: "path \"secret/*\" {}".to_owned(),
                },
            );
        let (mut app, mut rx) = App::new(Config::new("http://vault", "token"), Arc::clone(&vault));
        app.state = AppState::Main(Mode::Policies);

        let generation = app.store.bump_generation();
        app.apply(Msg::PoliciesLoaded {
            generation,
            entries: vec![PolicyEntry {
                name: "team".to_owned(),
            }],
        });

        // Then: the selected preview load is spawned after the list enters the store.
        let mut loaded = false;
        for _ in 0..4 {
            let Ok(Some(msg)) =
                tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv()).await
            else {
                break;
            };
            loaded = matches!(msg, Msg::PolicyLoaded { .. });
            app.apply(msg);
            if loaded {
                break;
            }
        }
        assert!(loaded);
        assert!(matches!(
            app.policies_model().preview,
            PolicyPreview::Loaded { .. }
        ));
    }

    #[test]
    fn late_policy_load_for_unselected_policy_does_not_open_editor() {
        let (mut app, _rx, _vault) = test_app();
        app.state = AppState::Main(Mode::Policies);
        let generation = app.store.bump_generation();
        app.apply(Msg::PoliciesLoaded {
            generation,
            entries: vec![
                PolicyEntry {
                    name: "alpha".to_owned(),
                },
                PolicyEntry {
                    name: "beta".to_owned(),
                },
            ],
        });
        app.policy_can_write = true;

        // When: `e` on alpha (document not cached yet) then move to beta.
        app.handle_input(key(KeyCode::Char('e')));
        assert!(app.take_editor_request().is_none());
        app.handle_input(key(KeyCode::Char('j')));
        assert_eq!(app.selected_policy_name().as_deref(), Some("beta"));

        // Then: alpha's late document load does not open an editor for it.
        app.apply(Msg::PolicyLoaded {
            generation,
            name: "alpha".to_owned(),
            document: PolicyDocument {
                name: "alpha".to_owned(),
                policy: "path \"secret/*\" {}".to_owned(),
            },
        });
        assert!(app.take_editor_request().is_none());
    }

    #[test]
    fn edit_without_policy_permission_sets_error_and_no_request() {
        let (mut app, _rx, _vault) = test_app();
        app.state = AppState::Main(Mode::Policies);
        app.policy_can_write = false;
        let generation = app.store.bump_generation();
        app.apply(Msg::PoliciesLoaded {
            generation,
            entries: vec![PolicyEntry {
                name: "team".to_owned(),
            }],
        });
        app.handle_input(key(KeyCode::Char('e')));
        assert!(app.take_editor_request().is_none());
        assert_eq!(app.status.as_ref().map(|s| s.kind), Some(StatusKind::Error));
    }

    #[test]
    fn edit_with_cached_policy_emits_editor_request() {
        let (mut app, _rx, _vault) = test_app();
        app.state = AppState::Main(Mode::Policies);
        let generation = app.store.bump_generation();
        app.apply(Msg::PoliciesLoaded {
            generation,
            entries: vec![PolicyEntry {
                name: "team".to_owned(),
            }],
        });
        app.apply(Msg::PolicyLoaded {
            generation,
            name: "team".to_owned(),
            document: PolicyDocument {
                name: "team".to_owned(),
                policy: "path \"secret/*\" {}".to_owned(),
            },
        });
        app.policy_can_write = true;
        app.handle_input(key(KeyCode::Char('e')));
        let request = app.take_editor_request();
        assert!(request.is_some());
        assert_eq!(
            request.as_ref().map(|value| value.buffer.extension),
            Some(".hcl")
        );
    }

    #[test]
    fn complete_editor_changed_opens_save_prompt() {
        let (mut app, _rx, _vault) = test_app();
        let request = EditorRequest {
            target: EditorTarget::Policy {
                name: "team".to_owned(),
                original_policy: "old".to_owned(),
            },
            buffer: EditBuffer {
                initial_text: "old".to_owned(),
                file_stem: "team".to_owned(),
                extension: ".hcl",
            },
        };
        app.complete_editor_request(request, Ok(EditOutcome::Changed("new".to_owned())));
        assert_eq!(
            app.prompt.as_ref().map(|prompt| prompt.kind),
            Some(PromptKind::SavePolicy)
        );
    }

    #[tokio::test]
    async fn save_policy_confirm_writes_and_sets_success() {
        let (mut app, mut rx, vault) = test_app();
        let request = EditorRequest {
            target: EditorTarget::Policy {
                name: "team".to_owned(),
                original_policy: "old".to_owned(),
            },
            buffer: EditBuffer {
                initial_text: "old".to_owned(),
                file_stem: "team".to_owned(),
                extension: ".hcl",
            },
        };
        app.complete_editor_request(request, Ok(EditOutcome::Changed("new".to_owned())));
        app.handle_input(key(KeyCode::Enter));
        for _ in 0..4 {
            let Some(msg) = rx.recv().await else {
                break;
            };
            app.apply(msg);
            if app
                .status
                .as_ref()
                .is_some_and(|status| status.text == "policy 'team' saved")
            {
                break;
            }
        }
        assert!(
            vault
                .policy_writes()
                .iter()
                .any(|(name, policy)| name == "team" && policy == "new")
        );
        assert_eq!(
            app.status.as_ref().map(|status| status.text.as_str()),
            Some("policy 'team' saved")
        );
    }

    #[test]
    fn new_policy_prompt_to_capability_to_editor_request() {
        let (mut app, _rx, _vault) = test_app();
        app.state = AppState::Main(Mode::Policies);
        app.handle_input(key(KeyCode::Char('n')));
        for ch in "newpolicy".chars() {
            app.handle_input(key(KeyCode::Char(ch)));
        }
        app.handle_input(key(KeyCode::Enter));
        let generation = app.store.generation();
        app.apply(Msg::PolicyCapabilities {
            generation,
            name: "newpolicy".to_owned(),
            writable: true,
        });
        assert!(app.take_editor_request().is_some());
    }

    #[test]
    fn new_secret_prompt_opens_and_edits_with_chars() {
        // Given: a writable token in the secrets view.
        let (mut app, _rx, _vault) = test_app();
        app.state = AppState::Main(Mode::Secrets);
        app.can_write = true;

        // When: `n` opens the prompt and characters are typed.
        app.handle_input(key(KeyCode::Char('n')));
        app.handle_input(key(KeyCode::Char('b')));
        app.handle_input(key(KeyCode::Char('2')));

        // Then: the prompt holds the typed name.
        let prompt = app.prompt.as_ref().expect("prompt");
        assert_eq!(prompt.kind, PromptKind::NewSecret);
        assert_eq!(prompt.input, "b2");

        // When: Esc cancels.
        app.handle_input(key(KeyCode::Esc));
        // Then: the prompt disappears.
        assert_eq!(app.prompt, None);
    }

    #[tokio::test]
    async fn creates_new_secret_when_prompt_submitted() {
        // Given: a writable token in the secrets view at the engine root.
        let (mut app, mut rx, vault) = test_app();
        app.state = AppState::Main(Mode::Secrets);
        app.secrets_engine = SecretPath::new("secret");
        app.secrets_path = SecretPath::root();
        app.can_write = true;

        // When: `n`, a name and Enter are pressed.
        app.handle_input(key(KeyCode::Char('n')));
        for ch in "brand-new".chars() {
            app.handle_input(key(KeyCode::Char(ch)));
        }
        app.handle_input(key(KeyCode::Enter));

        // Then: a creation message arrives and the empty-data write is recorded.
        let msg = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("creation message")
            .expect("channel open");
        assert!(matches!(msg, Msg::SecretCreated { .. }));
        let created = {
            let writes = vault.writes.lock().expect("writes lock");
            writes.iter().any(|(mount, path, data)| {
                mount == &SecretPath::new("secret")
                    && path == &SecretPath::new("brand-new")
                    && data.is_empty()
            })
        };
        assert!(created);
    }

    #[test]
    fn add_key_when_prompt_submitted_inserts_into_secret_data() {
        // Given: an open secret with a writable token.
        let (mut app, _rx, _vault) = test_app();
        let kv = kv_data("pw");
        let original = kv.data.clone();
        app.secret_data = Some(SecretDataUi {
            key: SecretPath::new("team/creds"),
            data: kv,
            selected: 0,
            mode: DataMode::ListOnly,
            original_data: original,
        });
        app.state = AppState::Main(Mode::SecretData);
        app.can_write = true;

        // When: `a`, a key name and Enter are pressed.
        app.handle_input(key(KeyCode::Char('a')));
        for ch in "apikey".chars() {
            app.handle_input(key(KeyCode::Char(ch)));
        }
        app.handle_input(key(KeyCode::Enter));

        // Then: the new key is inserted, selected, and in edit mode.
        let ui = app.secret_data.as_ref().expect("secret data");
        assert!(ui.data.data.contains_key("apikey"));
        assert!(ui.original_data.contains_key("apikey"));
        assert_eq!(
            ui.mode,
            DataMode::Edit {
                key: "apikey".to_owned(),
                text: String::new()
            }
        );
    }

    #[test]
    fn add_key_when_prompt_submitted_rejects_duplicates() {
        // Given: an open secret that already has the key.
        let (mut app, _rx, _vault) = test_app();
        let kv = kv_data("pw");
        let original = kv.data.clone();
        app.secret_data = Some(SecretDataUi {
            key: SecretPath::new("team/creds"),
            data: kv,
            selected: 0,
            mode: DataMode::ListOnly,
            original_data: original,
        });
        app.state = AppState::Main(Mode::SecretData);
        app.can_write = true;

        // When: `a` with an existing key name.
        app.handle_input(key(KeyCode::Char('a')));
        for ch in "password".chars() {
            app.handle_input(key(KeyCode::Char(ch)));
        }
        app.handle_input(key(KeyCode::Enter));

        // Then: the prompt stays open with a duplicate error.
        let prompt = app.prompt.as_ref().expect("prompt");
        assert_eq!(prompt.error.as_deref(), Some("key already exists"));
    }

    #[test]
    fn delete_prompt_gated_by_permission_when_not_deletable() {
        // Given: a token without delete capability in the secrets view.
        let (mut app, _rx, _vault) = test_app();
        app.spawn_initial_loads();
        app.state = AppState::Main(Mode::Secrets);
        app.secrets_engine = SecretPath::new("secret");
        app.secrets_path = SecretPath::new("team/");
        app.can_delete = false;

        // When: `d` is pressed on a leaf.
        app.handle_input(key(KeyCode::Char('d')));

        // Then: no prompt opens and a permission error is shown.
        assert_eq!(app.prompt, None);
        assert_eq!(app.status.as_ref().map(|s| s.kind), Some(StatusKind::Error));
    }

    #[test]
    fn delete_prompt_rejects_directories() {
        // Given: a deletable token with a directory selected.
        let (mut app, _rx, _vault) = test_app();
        app.state = AppState::Main(Mode::Secrets);
        app.secrets_engine = SecretPath::new("secret");
        app.secrets_path = SecretPath::root();
        app.can_delete = true;
        app.apply(Msg::SecretsLoaded {
            generation: 0,
            key: app.current_secrets_key(),
            entries: vec![SecretEntry::dir("team/"), SecretEntry::leaf("root")],
        });
        app.secrets_selected = 0;

        // When: `d` is pressed on the root listing where a directory is first.
        app.handle_input(key(KeyCode::Char('d')));

        // Then: no confirmation opens; a virtual-directory hint is shown.
        assert_eq!(app.prompt, None);
        assert_eq!(app.status.as_ref().map(|s| s.kind), Some(StatusKind::Info));
    }

    #[tokio::test]
    async fn delete_confirm_spawns_metadata_delete_and_reports_success() {
        // Given: a deletable token with a leaf selected in the secrets view.
        let (mut app, mut rx, vault) = test_app();
        app.state = AppState::Main(Mode::Secrets);
        app.secrets_engine = SecretPath::new("secret");
        app.secrets_path = SecretPath::new("team/");
        app.can_delete = true;
        app.apply(Msg::SecretsLoaded {
            generation: 0,
            key: app.current_secrets_key(),
            entries: vec![SecretEntry::leaf("creds")],
        });
        app.secrets_selected = 0;

        // When: `d` opens the confirmation and Enter confirms it.
        app.handle_input(key(KeyCode::Char('d')));
        assert_eq!(app.secrets_model().entries[0].name.as_str(), "creds");
        app.handle_input(key(KeyCode::Enter));

        // Then: the deletion message surfaces once the spawned task completes.
        for _ in 0..4 {
            let msg = rx.recv().await.expect("message");
            app.apply(msg);
            if app
                .status
                .as_ref()
                .is_some_and(|status| status.text == "secret 'creds' deleted")
            {
                break;
            }
        }
        assert_eq!(
            app.status.as_ref().map(|status| status.text.as_str()),
            Some("secret 'creds' deleted")
        );
        // And: a metadata delete was issued for the exact path.
        let deleted = {
            let deletes = vault.deletes.lock().expect("deletes lock");
            deletes.iter().any(|(mount, path)| {
                mount == &SecretPath::new("secret") && path == &SecretPath::new("team/creds")
            })
        };
        assert!(deleted);
    }

    async fn drain_up_to(
        app: &mut App<FakeVault>,
        rx: &mut mpsc::UnboundedReceiver<Msg>,
        max: usize,
    ) {
        for _ in 0..max {
            match tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await {
                Ok(Some(msg)) => app.apply(msg),
                _ => break,
            }
        }
    }

    #[test]
    fn colon_opens_command_prompt_outside_editor() {
        // Given: the engines view.
        let (mut app, _rx, _vault) = test_app();

        // When: `:` is pressed.
        app.handle_input(key(KeyCode::Char(':')));

        // Then: the command prompt opens.
        assert_eq!(
            app.prompt.as_ref().map(|prompt| prompt.kind),
            Some(PromptKind::Command)
        );
    }

    #[test]
    fn colon_is_literal_text_inside_secret_editor() {
        // Given: an open secret in edit mode.
        let (mut app, _rx, _vault) = test_app();
        let kv = kv_data("pw");
        let original = kv.data.clone();
        app.secret_data = Some(SecretDataUi {
            key: SecretPath::new("team/creds"),
            data: kv,
            selected: 0,
            mode: DataMode::Edit {
                key: "password".to_owned(),
                text: String::new(),
            },
            original_data: original,
        });
        app.state = AppState::Main(Mode::SecretData);

        // When: `:` is pressed while editing.
        app.handle_input(key(KeyCode::Char(':')));

        // Then: it is typed into the value rather than opening the palette.
        assert_eq!(app.prompt, None);
        let ui = app.secret_data.as_ref().expect("secret data");
        assert_eq!(
            ui.mode,
            DataMode::Edit {
                key: "password".to_owned(),
                text: ":".to_owned()
            }
        );
    }

    #[tokio::test]
    async fn command_token_opens_inspector_with_details_and_capabilities() {
        // Given: the engines view with a token that may manage tokens.
        let (mut app, mut rx, _vault) = test_app();

        // When: `:token` is submitted.
        app.handle_input(key(KeyCode::Char(':')));
        for ch in "token".chars() {
            app.handle_input(key(KeyCode::Char(ch)));
        }
        app.handle_input(key(KeyCode::Enter));

        // Then: the inspector is shown with loaded details and probed capabilities.
        assert_eq!(app.state, AppState::Main(Mode::Token));
        drain_up_to(&mut app, &mut rx, 6).await;
        assert!(app.token_model().loaded);
        assert!(app.token_can_create);
        assert!(app.token_can_wrap);
    }

    #[tokio::test]
    async fn renew_token_reports_success() {
        // Given: an open token inspector.
        let (mut app, mut rx, _vault) = test_app();
        app.state = AppState::Main(Mode::Token);
        app.token_details = Some(TokenInfo::default());

        // When: `r` renews the token.
        app.handle_input(key(KeyCode::Char('r')));
        drain_up_to(&mut app, &mut rx, 4).await;

        // Then: a success status is surfaced.
        assert_eq!(
            app.status.as_ref().map(|status| status.text.as_str()),
            Some("token renewed")
        );
    }

    #[tokio::test]
    async fn child_token_prompt_chain_mints_token_shown_once() {
        // Given: an open token inspector with create rights.
        let (mut app, mut rx, _vault) = test_app();
        app.state = AppState::Main(Mode::Token);
        app.token_details = Some(TokenInfo::default());
        app.token_can_create = true;

        // When: `n` drives the policies -> ttl -> uses prompt chain.
        app.handle_input(key(KeyCode::Char('n')));
        assert_eq!(
            app.prompt.as_ref().map(|prompt| prompt.kind),
            Some(PromptKind::ChildTokenPolicies)
        );
        for ch in "default,app".chars() {
            app.handle_input(key(KeyCode::Char(ch)));
        }
        app.handle_input(key(KeyCode::Enter));
        assert_eq!(
            app.prompt.as_ref().map(|prompt| prompt.kind),
            Some(PromptKind::ChildTokenTtl)
        );
        for ch in "1h".chars() {
            app.handle_input(key(KeyCode::Char(ch)));
        }
        app.handle_input(key(KeyCode::Enter));
        assert_eq!(
            app.prompt.as_ref().map(|prompt| prompt.kind),
            Some(PromptKind::ChildTokenUses)
        );
        app.handle_input(key(KeyCode::Char('3')));
        app.handle_input(key(KeyCode::Enter));
        drain_up_to(&mut app, &mut rx, 4).await;

        // Then: the minted token is shown once in the preview pane with a warning.
        let pane = app.token_model().pane.expect("pane");
        assert_eq!(pane.title, "New Token (shown once)");
        assert_eq!(pane.body, "child-token-value");
        assert!(pane.warning.is_some());
    }

    #[tokio::test]
    async fn unwrap_command_shows_payload_in_pane() {
        // Given: the engines view.
        let (mut app, mut rx, _vault) = test_app();

        // When: `:unwrap` is submitted with a wrapping token.
        app.handle_input(key(KeyCode::Char(':')));
        for ch in "unwrap".chars() {
            app.handle_input(key(KeyCode::Char(ch)));
        }
        app.handle_input(key(KeyCode::Enter));
        assert_eq!(
            app.prompt.as_ref().map(|prompt| prompt.kind),
            Some(PromptKind::UnwrapToken)
        );
        for ch in "hvs.wrapping".chars() {
            app.handle_input(key(KeyCode::Char(ch)));
        }
        app.handle_input(key(KeyCode::Enter));
        drain_up_to(&mut app, &mut rx, 6).await;

        // Then: the inspector shows the pretty-printed payload.
        assert_eq!(app.state, AppState::Main(Mode::Token));
        let pane = app.token_model().pane.expect("pane");
        assert!(pane.body.contains("hunter2"));
    }

    #[test]
    fn copy_token_pane_copies_the_payload() {
        // Given: a token inspector showing an unwrapped payload.
        let (mut app, _rx, _vault) = test_app();
        app.state = AppState::Main(Mode::Token);
        app.clipboard = Box::<TestClipboard>::default();
        app.token_pane = Some(TokenPane::Unwrapped("{\"a\":1}".to_owned()));

        // When: `c` is pressed.
        app.handle_input(key(KeyCode::Char('c')));

        // Then: the payload is copied.
        assert_eq!(
            app.status.as_ref().map(|status| status.text.as_str()),
            Some("Copied to clipboard")
        );
    }

    #[test]
    fn copy_token_pane_without_payload_reports_nothing_to_copy() {
        // Given: a token inspector with no preview pane.
        let (mut app, _rx, _vault) = test_app();
        app.state = AppState::Main(Mode::Token);
        app.token_details = Some(TokenInfo::default());

        // When: `c` is pressed.
        app.handle_input(key(KeyCode::Char('c')));

        // Then: an informational status is shown.
        assert_eq!(
            app.status.as_ref().map(|status| status.text.as_str()),
            Some("nothing to copy")
        );
    }

    #[test]
    fn unknown_command_keeps_prompt_open_with_error() {
        // Given: the command palette.
        let (mut app, _rx, _vault) = test_app();
        app.handle_input(key(KeyCode::Char(':')));
        for ch in "nope".chars() {
            app.handle_input(key(KeyCode::Char(ch)));
        }

        // When: an unknown command is submitted.
        app.handle_input(key(KeyCode::Enter));

        // Then: the prompt stays open with an explanatory error.
        let prompt = app.prompt.as_ref().expect("prompt");
        assert_eq!(prompt.kind, PromptKind::Command);
        assert!(prompt.error.is_some());
    }

    #[test]
    fn child_token_creation_gated_when_capability_missing() {
        // Given: a token with a resolved probe that denies child-token creation.
        let (mut app, _rx, _vault) = test_app();
        app.state = AppState::Main(Mode::Token);
        app.token_details = Some(TokenInfo::default());
        app.token_caps_loaded = true;
        app.token_can_create = false;

        // When: `n` is pressed.
        app.handle_input(key(KeyCode::Char('n')));

        // Then: no prompt opens and a permission error is shown.
        assert_eq!(app.prompt, None);
        assert_eq!(
            app.status.as_ref().map(|status| status.kind),
            Some(StatusKind::Error)
        );
    }

    #[test]
    fn child_token_prompt_denies_at_submit_while_capabilities_pending() {
        // Given: capabilities still probing (fail-closed) so the prompt is allowed to open.
        let (mut app, _rx, _vault) = test_app();
        app.state = AppState::Main(Mode::Token);
        app.token_details = Some(TokenInfo::default());
        app.token_caps_loaded = false;
        app.token_can_create = false;

        // When: `n` opens the chain and all three prompts are submitted.
        app.handle_input(key(KeyCode::Char('n')));
        assert_eq!(
            app.prompt.as_ref().map(|prompt| prompt.kind),
            Some(PromptKind::ChildTokenPolicies)
        );
        for ch in "default".chars() {
            app.handle_input(key(KeyCode::Char(ch)));
        }
        app.handle_input(key(KeyCode::Enter));
        app.handle_input(key(KeyCode::Enter));
        app.handle_input(key(KeyCode::Enter));

        // Then: minting is refused at submit and no prompt remains.
        assert_eq!(app.prompt, None);
        assert_eq!(
            app.status.as_ref().map(|status| status.kind),
            Some(StatusKind::Error)
        );
    }

    #[test]
    fn leaving_token_inspector_discards_shown_token() {
        // Given: a token inspector displaying a one-time payload.
        let (mut app, _rx, _vault) = test_app();
        app.state = AppState::Main(Mode::Token);
        app.token_details = Some(TokenInfo::default());
        app.token_pane = Some(TokenPane::Unwrapped("secret-payload".to_owned()));

        // When: the inspector is left.
        app.handle_input(key(KeyCode::Esc));

        // Then: the payload is no longer held in memory.
        assert!(app.token_pane.is_none());
        assert_eq!(app.state, AppState::Main(Mode::Engines));
    }

    #[test]
    fn escape_returns_from_token_inspector_to_previous_mode() {
        // Given: the token inspector opened from the secret data view.
        let (mut app, _rx, _vault) = test_app();
        app.state = AppState::Main(Mode::SecretData);
        app.open_token_view();
        assert_eq!(app.state, AppState::Main(Mode::Token));

        // When: Esc is pressed.
        app.handle_input(key(KeyCode::Esc));

        // Then: the previous mode is restored.
        assert_eq!(app.state, AppState::Main(Mode::SecretData));
    }
}
