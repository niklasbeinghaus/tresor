//! Application orchestration, input handling, background tasks, and root drawing.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use secrecy::{ExposeSecret as _, SecretString};
use tokio::sync::mpsc;

use crate::clipboard::{TextClipboard, default_clipboard};
use crate::config::Config;
use crate::constants::{NA_VALUE, STATUS_EXPIRY_SECS, keys};
use crate::model::{HealthInfo, KvData, SecretEntry, TokenInfo, VersionMeta};
use crate::path::SecretPath;
use crate::state::Mode;
use crate::store::{CacheKey, Msg, Store};
use crate::theme::Theme;
use crate::ui::commands::{Page, Permission, draw_commands};
use crate::ui::engines::{EnginesModel, draw_engines};
use crate::ui::header::{HeaderModel, StatusKind, StatusLine, draw_header};
use crate::ui::modal::{ModalField, ModalModel, draw_modal};
use crate::ui::prompt::{PromptKind, PromptModel, draw_prompt};
use crate::ui::secret_data::{DataMode, KeyRow, SecretDataModel, draw_secret_data};
use crate::ui::secrets::{SecretsModel, draw_secrets, sort_entries};
use crate::ui::versions::{VersionRow, VersionsModel, draw_versions};
use crate::vault::{VaultApi, VaultError};

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
    /// Optional exact text expected for destructive confirmations.
    pub expected: Option<String>,
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

/// Version-preview state owned by the app.
#[derive(Debug, Clone)]
pub struct VersionPreviewUi {
    /// Loaded version payload.
    pub data: KvData,
    /// Version number for this preview payload.
    pub version: u64,
    /// Selected preview key index.
    pub selected: usize,
    /// Preview display mode (`ListOnly`/`Preview` only).
    pub mode: DataMode,
}

/// Secret version-history state owned by the app.
#[derive(Debug, Clone)]
pub struct VersionsUi {
    /// Full leaf path inside the mounted engine.
    pub key: SecretPath,
    /// Current version number from metadata.
    pub current_version: u64,
    /// Loaded versions sorted newest-first.
    pub versions: Vec<VersionMeta>,
    /// Selected version row index.
    pub selected: usize,
    /// Optional loaded preview for the selected version.
    pub preview: Option<VersionPreviewUi>,
}

/// Running TUI application with injectable Vault API.
#[allow(
    clippy::struct_excessive_bools,
    reason = "capability bits are modeled explicitly for command gating and prompt checks"
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
    /// Current version-history UI state.
    pub versions: Option<VersionsUi>,
    /// Token may create secrets at the current context (permission gate).
    pub can_create: bool,
    /// Token may update secrets at the current context (permission gate).
    pub can_update: bool,
    /// Token may soft-delete secret versions at the current context.
    pub can_soft_delete: bool,
    /// Token may metadata-delete secret paths at the current context.
    pub can_metadata_delete: bool,
    /// Token may destroy secret versions at the current context.
    pub can_destroy: bool,
    /// Token may undelete secret versions at the current context.
    pub can_undelete: bool,
    /// Active input prompt, if any.
    pub prompt: Option<PromptState>,
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
                versions: None,
                can_create: false,
                can_update: false,
                can_soft_delete: false,
                can_metadata_delete: false,
                can_destroy: false,
                can_undelete: false,
                prompt: None,
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
        match self.state {
            AppState::ConfigInput => self.handle_config_input(key),
            AppState::Main(Mode::Config) => false,
            AppState::Main(Mode::Engines) => self.handle_engines_input(key),
            AppState::Main(Mode::Secrets) => self.handle_secrets_input(key),
            AppState::Main(Mode::SecretData) => self.handle_secret_data_input(key),
            AppState::Main(Mode::Versions) => self.handle_versions_input(key),
        }
    }

    /// Folds a background message into app/store state.
    #[allow(
        clippy::too_many_lines,
        reason = "single message fold entrypoint keeps app state transitions centralized"
    )]
    pub fn apply(&mut self, msg: Msg) {
        self.pending = false;
        let is_current = msg.generation() == self.store.generation();
        if !is_current {
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
                self.versions = None;
                self.secret_data = None;
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
            Msg::SecretMetadataDeleted { key, .. } => {
                let name = key.path.child_name();
                self.set_status(
                    StatusKind::Success,
                    format!("secret '{}' deleted", name.as_str()),
                );
                self.spawn_load_secrets(self.current_secrets_key());
            }
            Msg::VersionsLoaded { key, history, .. } => {
                if let Some(secret) = &self.secret_data {
                    if secret.key == key.path {
                        self.versions = Some(VersionsUi {
                            key: key.path.clone(),
                            current_version: history.current_version,
                            versions: history.versions.clone(),
                            selected: 0,
                            preview: None,
                        });
                        self.state = AppState::Main(Mode::Versions);
                    }
                }
            }
            Msg::SecretVersionLoaded {
                key, version, data, ..
            } => {
                if let Some(versions) = self.versions.as_mut() {
                    if versions.key == key.path {
                        let selected_version = versions
                            .versions
                            .get(
                                versions
                                    .selected
                                    .min(versions.versions.len().saturating_sub(1)),
                            )
                            .map(|item| item.version);
                        if selected_version == Some(*version) {
                            versions.preview = Some(VersionPreviewUi {
                                data: data.clone(),
                                version: *version,
                                selected: 0,
                                mode: DataMode::ListOnly,
                            });
                            let text = format!("loaded version {version}");
                            self.set_status(StatusKind::Info, text);
                        }
                    }
                }
            }
            Msg::SecretVersionDeleted { key, version, .. } => {
                self.set_status(StatusKind::Success, format!("version {version} deleted"));
                self.spawn_load_versions(key.clone());
            }
            Msg::SecretVersionUndeleted { key, version, .. } => {
                self.set_status(StatusKind::Success, format!("version {version} undeleted"));
                self.spawn_load_versions(key.clone());
            }
            Msg::SecretVersionDestroyed { key, version, .. } => {
                self.set_status(StatusKind::Success, format!("version {version} destroyed"));
                self.spawn_load_versions(key.clone());
            }
            Msg::SecretVersionRestored {
                key,
                source_version,
                ..
            } => {
                self.set_status(
                    StatusKind::Success,
                    format!(
                        "version {source_version} restored as latest; values were written as strings"
                    ),
                );
                // Only the version history is reloaded here: a concurrent
                // secrets-listing load would bump the generation again and make
                // this reload stale, so the new version would never appear.
                self.spawn_load_versions(key.clone());
            }
            Msg::Capabilities { .. }
            | Msg::EnginesLoaded { .. }
            | Msg::SecretsLoaded { .. }
            | Msg::HardRefreshed { .. } => {}
        }

        let mut cache_msg = msg;
        let capability_update = match &cache_msg {
            Msg::Capabilities {
                create,
                update,
                soft_delete,
                metadata_delete,
                destroy,
                undelete,
                ..
            } => Some((
                *create,
                *update,
                *soft_delete,
                *metadata_delete,
                *destroy,
                *undelete,
            )),
            _ => None,
        };
        if let Msg::SecretsLoaded { entries, .. } = &mut cache_msg {
            sort_entries(entries);
        }
        let accepted = self.store.apply(cache_msg);
        if accepted {
            if let Some((create, update, soft_delete, metadata_delete, destroy, undelete)) =
                capability_update
            {
                self.can_create = create;
                self.can_update = update;
                self.can_soft_delete = soft_delete;
                self.can_metadata_delete = metadata_delete;
                self.can_destroy = destroy;
                self.can_undelete = undelete;
            }
        }
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
            create: self.can_create,
            update: self.can_update,
            soft_delete: self.can_soft_delete,
            metadata_delete: self.can_metadata_delete,
            destroy: self.can_destroy,
            undelete: self.can_undelete,
        }
    }

    /// The command-bar page for the current app state.
    pub const fn commands_page(&self) -> Page {
        match self.state {
            AppState::ConfigInput | AppState::Main(Mode::Config) => Page::Config,
            AppState::Main(Mode::Engines) => Page::Engines,
            AppState::Main(Mode::Secrets) => Page::Secrets,
            AppState::Main(Mode::SecretData) => Page::SecretData,
            AppState::Main(Mode::Versions) => Page::Versions,
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
            read_only: false,
        })
    }

    /// Builds the pure versions render model.
    pub fn versions_model(&self) -> Option<VersionsModel> {
        let versions = self.versions.as_ref()?;
        let rows = versions
            .versions
            .iter()
            .map(|item| VersionRow {
                version: item.version,
                created_time: item.created_time.clone(),
                deletion_time: item.deletion_time.clone(),
                destroyed: item.destroyed,
                is_current: item.is_current,
            })
            .collect();
        let preview = versions.preview.as_ref().map(|preview_ui| {
            let keys = preview_ui
                .data
                .data
                .keys()
                .map(|key| KeyRow { label: key.clone() })
                .collect();
            SecretDataModel {
                secret_name: versions.key.as_str().to_owned(),
                engine: self.secrets_engine.as_str().to_owned(),
                version: preview_ui.data.metadata.version,
                created_time: preview_ui.data.metadata.created_time.clone(),
                keys,
                selected: preview_ui.selected,
                mode: preview_ui.mode.clone(),
                read_only: true,
            }
        });
        Some(VersionsModel {
            secret_name: versions.key.as_str().to_owned(),
            engine: self.secrets_engine.as_str().to_owned(),
            rows,
            selected: versions.selected,
            preview,
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
        draw_commands(
            frame,
            *commands_area,
            self.commands_page(),
            self.permission(),
            &self.theme,
        );
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
            AppState::Main(Mode::SecretData) => {
                if let Some(model) = self.secret_data_model() {
                    draw_secret_data(frame, *body_area, &model, &self.theme);
                }
            }
            AppState::Main(Mode::Versions) => {
                if let Some(model) = self.versions_model() {
                    draw_versions(frame, *body_area, &model, &self.theme);
                }
            }
        }
        if let Some(prompt) = &self.prompt {
            let model = PromptModel {
                kind: prompt.kind,
                input: prompt.input.clone(),
                error: prompt.error.clone(),
                expected: prompt.expected.clone(),
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
            KeyCode::Char(keys::METADATA_DELETE) => {
                self.open_delete_secret_metadata_prompt();
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

    fn handle_secret_data_input(&mut self, key: KeyEvent) -> bool {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('s') {
            self.save_secret();
            return false;
        }
        match key.code {
            KeyCode::Esc => {
                self.back_from_secret_data();
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
                keys::VERSIONS => {
                    self.open_versions_pane();
                    false
                }
                'd' => {
                    self.open_soft_delete_latest_prompt();
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

    fn handle_versions_input(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => {
                self.back_from_versions();
                false
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some(versions) = self.versions.as_mut() {
                    versions.selected = versions.selected.saturating_sub(1);
                    versions.preview = None;
                }
                false
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(versions) = self.versions.as_mut() {
                    versions.selected = next_index(versions.selected, versions.versions.len());
                    versions.preview = None;
                }
                false
            }
            KeyCode::Enter => {
                self.load_selected_version_preview();
                false
            }
            KeyCode::Tab => {
                self.move_version_preview_key_down();
                false
            }
            KeyCode::Char(keys::REVEAL) => {
                self.reveal_selected_version_preview_value();
                false
            }
            KeyCode::Char(keys::COPY) => {
                self.copy_selected_version_preview_value();
                false
            }
            KeyCode::Char(keys::RESTORE) => {
                self.restore_selected_version();
                false
            }
            KeyCode::Char(keys::UNDELETE) => {
                self.undelete_selected_version();
                false
            }
            KeyCode::Char(keys::DESTROY) => {
                self.open_destroy_version_prompt();
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

    fn open_selected_engine(&mut self) {
        let Some(entry) = self.store.engines().get(self.engines_selected).cloned() else {
            return;
        };
        self.secrets_engine = entry.name;
        self.secrets_path = SecretPath::root();
        self.secrets_selected = 0;
        self.state = AppState::Main(Mode::Secrets);
        self.load_current_secrets();
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
            self.load_current_secrets();
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
            self.reset_permissions();
            self.state = AppState::Main(Mode::Engines);
        } else {
            self.secrets_path = self.secrets_path.parent();
            self.secrets_selected = 0;
            self.load_current_secrets();
        }
    }

    fn back_from_secret_data(&mut self) {
        self.state = AppState::Main(Mode::Secrets);
        self.load_current_secrets();
    }

    /// Loads the current directory listing, or re-probes capabilities when it is
    /// already cached, so the command hints stay in sync with the context.
    fn load_current_secrets(&mut self) {
        let key = self.current_secrets_key();
        if self.store.secrets(&key).is_none() {
            self.spawn_load_secrets(key);
        } else {
            self.probe_secrets_capabilities();
        }
    }

    /// Re-probes capabilities for the current directory without reloading the
    /// cached listing; permissions stay cleared until the probe returns.
    fn probe_secrets_capabilities(&mut self) {
        self.reset_permissions();
        let mount = self.secrets_engine.clone();
        let path = self.secrets_path.clone();
        self.spawn_capabilities(self.store.generation(), &mount, &path, false);
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
        self.reset_permissions();
        let original_data = data.data.clone();
        self.secret_data = Some(SecretDataUi {
            key: key.path.clone(),
            data,
            selected: 0,
            mode: DataMode::ListOnly,
            original_data,
        });
        self.state = AppState::Main(Mode::SecretData);
        self.versions = None;
        let mount = self.secrets_engine.clone();
        let path = key.path.clone();
        self.spawn_capabilities(self.store.generation(), &mount, &path, true);
    }

    fn open_versions_pane(&mut self) {
        let Some(secret_key) = self.secret_data.as_ref().map(|secret| secret.key.clone()) else {
            return;
        };
        self.reset_permissions();
        let key = CacheKey {
            mount: self.secrets_engine.clone(),
            path: secret_key,
        };
        let generation = self.store.bump_generation();
        self.pending = true;
        self.spawn_load_versions_with_generation(key, generation);
    }

    fn back_from_versions(&mut self) {
        self.state = AppState::Main(Mode::SecretData);
        // A restore may have changed the latest version; re-read the open
        // secret so returning to the data view is not stale.
        if let Some(secret) = &self.secret_data {
            let key = CacheKey {
                mount: self.secrets_engine.clone(),
                path: secret.key.clone(),
            };
            self.spawn_load_secret(key);
        }
    }

    const fn reset_permissions(&mut self) {
        self.can_create = false;
        self.can_update = false;
        self.can_soft_delete = false;
        self.can_metadata_delete = false;
        self.can_destroy = false;
        self.can_undelete = false;
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

    fn selected_version_row(&self) -> Option<VersionMeta> {
        let versions = self.versions.as_ref()?;
        let index = versions
            .selected
            .min(versions.versions.len().saturating_sub(1));
        versions.versions.get(index).cloned()
    }

    fn selected_version_is_soft_deleted(&self) -> bool {
        self.selected_version_row()
            .and_then(|version| version.deletion_time)
            .is_some()
    }

    fn selected_version_is_destroyed(&self) -> bool {
        self.selected_version_row()
            .is_some_and(|version| version.destroyed)
    }

    fn selected_version_number(&self) -> Option<u64> {
        self.selected_version_row().map(|version| version.version)
    }

    fn load_selected_version_preview(&mut self) {
        if self.selected_version_is_destroyed() {
            self.set_status(StatusKind::Error, "destroyed versions cannot be previewed");
            return;
        }
        if self.selected_version_is_soft_deleted() {
            self.set_status(
                StatusKind::Info,
                "soft-deleted versions must be undeleted before preview",
            );
            return;
        }
        let Some(version) = self.selected_version_number() else {
            return;
        };
        let Some(versions) = &self.versions else {
            return;
        };
        self.spawn_load_version_preview(
            CacheKey {
                mount: self.secrets_engine.clone(),
                path: versions.key.clone(),
            },
            version,
        );
    }

    fn move_version_preview_key_down(&mut self) {
        let Some(versions) = self.versions.as_mut() else {
            return;
        };
        let Some(preview) = versions.preview.as_mut() else {
            return;
        };
        preview.selected = next_index(preview.selected, preview.data.data.len());
    }

    fn selected_version_preview_key(&self) -> Option<String> {
        let versions = self.versions.as_ref()?;
        let preview = versions.preview.as_ref()?;
        preview.data.data.keys().nth(preview.selected).cloned()
    }

    fn selected_version_preview_value(&self) -> Option<String> {
        let key = self.selected_version_preview_key()?;
        let versions = self.versions.as_ref()?;
        let preview = versions.preview.as_ref()?;
        preview
            .data
            .data
            .get(&key)
            .map(|value| value.expose_secret().to_owned())
    }

    fn reveal_selected_version_preview_value(&mut self) {
        let Some(key) = self.selected_version_preview_key() else {
            return;
        };
        let Some(value) = self.selected_version_preview_value() else {
            return;
        };
        if let Some(versions) = self.versions.as_mut() {
            if let Some(preview) = versions.preview.as_mut() {
                preview.mode = DataMode::Preview { key, value };
            }
        }
    }

    fn copy_selected_version_preview_value(&mut self) {
        let Some(value) = self.selected_version_preview_value() else {
            return;
        };
        match self.clipboard.copy(&value) {
            Ok(()) => self.set_status(StatusKind::Success, "Copied to clipboard"),
            Err(err) => self.set_status(StatusKind::Error, err.to_string()),
        }
    }

    fn restore_selected_version(&mut self) {
        if !self.can_update {
            self.set_status(StatusKind::Error, "no permission to restore versions here");
            return;
        }
        if self.selected_version_is_destroyed() {
            self.set_status(StatusKind::Error, "destroyed versions cannot be restored");
            return;
        }
        if self.selected_version_is_soft_deleted() {
            self.set_status(
                StatusKind::Info,
                "soft-deleted versions must be undeleted before restore",
            );
            return;
        }
        let Some(version) = self.selected_version_number() else {
            return;
        };
        let Some(versions) = &self.versions else {
            return;
        };
        self.spawn_restore_version(
            CacheKey {
                mount: self.secrets_engine.clone(),
                path: versions.key.clone(),
            },
            version,
        );
    }

    fn undelete_selected_version(&mut self) {
        if !self.can_undelete {
            self.set_status(StatusKind::Error, "no permission to undelete versions here");
            return;
        }
        if self.selected_version_is_destroyed() {
            self.set_status(StatusKind::Error, "destroyed versions cannot be undeleted");
            return;
        }
        let Some(version) = self.selected_version_number() else {
            return;
        };
        if !self.selected_version_is_soft_deleted() {
            self.set_status(
                StatusKind::Info,
                format!("version {version} is not deleted"),
            );
            return;
        }
        let Some(versions) = &self.versions else {
            return;
        };
        self.spawn_undelete_version(
            CacheKey {
                mount: self.secrets_engine.clone(),
                path: versions.key.clone(),
            },
            version,
        );
    }

    fn open_soft_delete_latest_prompt(&mut self) {
        if !self.can_soft_delete {
            self.set_status(
                StatusKind::Error,
                "no permission to soft-delete latest version here",
            );
            return;
        }
        let Some(secret) = &self.secret_data else {
            return;
        };
        let version = secret.data.metadata.version;
        let key = CacheKey {
            mount: self.secrets_engine.clone(),
            path: secret.key.clone(),
        };
        self.spawn_soft_delete_latest(key, version);
    }

    fn open_destroy_version_prompt(&mut self) {
        if !self.can_destroy {
            self.set_status(StatusKind::Error, "no permission to destroy versions here");
            return;
        }
        if self.selected_version_is_destroyed() {
            self.set_status(StatusKind::Info, "version is already destroyed");
            return;
        }
        let Some(version) = self.selected_version_number() else {
            return;
        };
        self.prompt = Some(PromptState {
            kind: PromptKind::DestroyVersion,
            input: String::new(),
            error: None,
            expected: Some(version.to_string()),
        });
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
        self.reset_permissions();
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
        let data_probe = if leaf {
            format!("{}/data/{}", mount.as_str(), path.as_str())
        } else {
            format!("{mount}/data/{path}{CAPABILITY_PROBE}")
        };
        let metadata_probe = format!("{mount}/metadata/{path}");
        let soft_delete_probe = format!("{mount}/delete/{path}");
        let destroy_probe = format!("{mount}/destroy/{path}");
        let undelete_probe = format!("{mount}/undelete/{path}");
        let paths = vec![
            data_probe.clone(),
            metadata_probe.clone(),
            soft_delete_probe.clone(),
            destroy_probe.clone(),
            undelete_probe.clone(),
        ];
        let vault = Arc::clone(&self.vault);
        self.spawn_msg(self.tx.clone(), async move {
            let (create, update, soft_delete, metadata_delete, destroy, undelete) =
                match tokio::time::timeout(TASK_TIMEOUT, vault.capabilities_self(&paths)).await {
                    Ok(Ok(caps)) => {
                        let data_caps = caps.get(&data_probe).map_or(&[][..], Vec::as_slice);
                        let metadata_caps =
                            caps.get(&metadata_probe).map_or(&[][..], Vec::as_slice);
                        let soft_delete_caps =
                            caps.get(&soft_delete_probe).map_or(&[][..], Vec::as_slice);
                        let destroy_caps = caps.get(&destroy_probe).map_or(&[][..], Vec::as_slice);
                        let undelete_caps =
                            caps.get(&undelete_probe).map_or(&[][..], Vec::as_slice);
                        (
                            caps_allow_create(data_caps),
                            caps_allow_update(data_caps),
                            caps_allow_soft_delete(soft_delete_caps),
                            caps_allow_delete(metadata_caps),
                            caps_allow_destroy(destroy_caps),
                            caps_allow_undelete(undelete_caps),
                        )
                    }
                    _ => (false, false, false, false, false, false),
                };
            Msg::Capabilities {
                generation,
                create,
                update,
                soft_delete,
                metadata_delete,
                destroy,
                undelete,
            }
        });
    }

    fn spawn_load_versions(&mut self, key: CacheKey) {
        let generation = self.store.bump_generation();
        self.pending = true;
        self.spawn_load_versions_with_generation(key, generation);
    }

    fn spawn_load_versions_with_generation(&mut self, key: CacheKey, generation: u64) {
        self.reset_permissions();
        let probe_mount = key.mount.clone();
        let probe_path = key.path.clone();
        let vault = Arc::clone(&self.vault);
        self.spawn_msg(self.tx.clone(), async move {
            match tokio::time::timeout(TASK_TIMEOUT, vault.read_kv_metadata(&key.mount, &key.path))
                .await
            {
                Ok(Ok(history)) => Msg::VersionsLoaded {
                    generation,
                    key,
                    history,
                },
                Ok(Err(err)) if err.status() == Some(404) => Msg::PathNotFound { generation, key },
                Ok(Err(err)) => Msg::Failure {
                    generation,
                    message: err.message(),
                },
                Err(_elapsed) => timeout_msg(generation),
            }
        });
        self.spawn_capabilities(generation, &probe_mount, &probe_path, true);
    }

    fn spawn_load_version_preview(&mut self, key: CacheKey, version: u64) {
        let generation = self.store.bump_generation();
        self.pending = true;
        let vault = Arc::clone(&self.vault);
        self.spawn_msg(self.tx.clone(), async move {
            match tokio::time::timeout(
                TASK_TIMEOUT,
                vault.read_kv_version(&key.mount, &key.path, version),
            )
            .await
            {
                Ok(Ok(data)) => Msg::SecretVersionLoaded {
                    generation,
                    key,
                    version,
                    data,
                },
                Ok(Err(err)) if err.status() == Some(404) => Msg::Failure {
                    generation,
                    message: format!("version {version} is unavailable: {}", err.message()),
                },
                Ok(Err(err)) => Msg::Failure {
                    generation,
                    message: err.message(),
                },
                Err(_elapsed) => timeout_msg(generation),
            }
        });
    }

    fn spawn_soft_delete_latest(&mut self, key: CacheKey, version: u64) {
        let generation = self.store.bump_generation();
        self.pending = true;
        let vault = Arc::clone(&self.vault);
        self.spawn_msg(self.tx.clone(), async move {
            match tokio::time::timeout(
                TASK_TIMEOUT,
                vault.delete_kv_secret_version(&key.mount, &key.path, version),
            )
            .await
            {
                Ok(Ok(())) => Msg::SecretVersionDeleted {
                    generation,
                    key,
                    version,
                },
                Ok(Err(err)) => Msg::Failure {
                    generation,
                    message: err.message(),
                },
                Err(_elapsed) => timeout_msg(generation),
            }
        });
    }

    fn spawn_undelete_version(&mut self, key: CacheKey, version: u64) {
        let generation = self.store.bump_generation();
        self.pending = true;
        let vault = Arc::clone(&self.vault);
        self.spawn_msg(self.tx.clone(), async move {
            match tokio::time::timeout(
                TASK_TIMEOUT,
                vault.undelete_kv_secret_version(&key.mount, &key.path, version),
            )
            .await
            {
                Ok(Ok(())) => Msg::SecretVersionUndeleted {
                    generation,
                    key,
                    version,
                },
                Ok(Err(err)) => Msg::Failure {
                    generation,
                    message: err.message(),
                },
                Err(_elapsed) => timeout_msg(generation),
            }
        });
    }

    fn spawn_destroy_version(&mut self, key: CacheKey, version: u64) {
        let generation = self.store.bump_generation();
        self.pending = true;
        let vault = Arc::clone(&self.vault);
        self.spawn_msg(self.tx.clone(), async move {
            match tokio::time::timeout(
                TASK_TIMEOUT,
                vault.destroy_kv_secret_version(&key.mount, &key.path, version),
            )
            .await
            {
                Ok(Ok(())) => Msg::SecretVersionDestroyed {
                    generation,
                    key,
                    version,
                },
                Ok(Err(err)) => Msg::Failure {
                    generation,
                    message: err.message(),
                },
                Err(_elapsed) => timeout_msg(generation),
            }
        });
    }

    fn spawn_restore_version(&mut self, key: CacheKey, version: u64) {
        let generation = self.store.bump_generation();
        self.pending = true;
        let vault = Arc::clone(&self.vault);
        self.spawn_msg(self.tx.clone(), async move {
            match tokio::time::timeout(
                TASK_TIMEOUT,
                vault.read_kv_version(&key.mount, &key.path, version),
            )
            .await
            {
                Ok(Ok(data)) => {
                    let missing = VaultError::Api {
                        status: 404,
                        path: key.path.as_str().to_owned(),
                        detail: "missing".to_owned(),
                    };
                    if data.metadata.deletion_time.is_some() || data.metadata.destroyed {
                        return Msg::Failure {
                            generation,
                            message: format!(
                                "version {version} is unavailable: {}",
                                missing.message()
                            ),
                        };
                    }
                    let payload: BTreeMap<String, String> = data
                        .data
                        .iter()
                        .map(|(k, v)| (k.clone(), v.expose_secret().to_owned()))
                        .collect();
                    match tokio::time::timeout(
                        TASK_TIMEOUT,
                        vault.write_kv_secret(&key.mount, &key.path, &payload),
                    )
                    .await
                    {
                        Ok(Ok(())) => Msg::SecretVersionRestored {
                            generation,
                            key,
                            source_version: version,
                        },
                        Ok(Err(err)) => Msg::Failure {
                            generation,
                            message: err.message(),
                        },
                        Err(_elapsed) => timeout_msg(generation),
                    }
                }
                Ok(Err(err)) => Msg::Failure {
                    generation,
                    message: err.message(),
                },
                Err(_elapsed) => timeout_msg(generation),
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

    fn open_new_secret_prompt(&mut self) {
        if !self.can_create {
            self.set_status(StatusKind::Error, "no permission to create secrets here");
            return;
        }
        self.prompt = Some(PromptState {
            kind: PromptKind::NewSecret,
            input: String::new(),
            error: None,
            expected: None,
        });
    }

    fn inside_secret_editor(&self) -> bool {
        matches!(
            self.secret_data.as_ref().map(|ui| &ui.mode),
            Some(DataMode::Edit { .. })
        )
    }

    /// Opens the delete confirmation for the selected leaf entry (directories
    /// are virtual in KV2 — their secrets must be removed individually).
    fn open_delete_secret_metadata_prompt(&mut self) {
        if !self.can_metadata_delete {
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
            expected: None,
        });
    }

    fn spawn_delete_secret_metadata(&mut self, key: CacheKey) {
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
                Ok(Ok(())) => Msg::SecretMetadataDeleted { generation, key },
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
        if !self.can_update {
            self.set_status(StatusKind::Error, "no permission to add keys here");
            return;
        }
        self.prompt = Some(PromptState {
            kind: PromptKind::NewKey,
            input: String::new(),
            error: None,
            expected: None,
        });
    }

    #[must_use]
    fn handle_prompt_input(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => self.prompt = None,
            KeyCode::Enter => self.submit_prompt(),
            KeyCode::Backspace => {
                if let Some(prompt) = self.prompt.as_mut() {
                    if prompt.kind.accepts_input() {
                        prompt.input.pop();
                    }
                }
            }
            KeyCode::Char(ch) => {
                if let Some(prompt) = self.prompt.as_mut() {
                    if prompt.kind.accepts_input() {
                        prompt.input.push(ch);
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
        if prompt.kind == PromptKind::DestroyVersion {
            let typed = prompt.input.trim().to_owned();
            let expected = prompt.expected.unwrap_or_default();
            self.destroy_version(&typed, &expected);
            return;
        }
        let name = prompt.input.trim().to_owned();
        if name.is_empty() {
            prompt.error = Some("name cannot be empty".to_owned());
            self.prompt = Some(prompt);
            return;
        }
        match prompt.kind {
            PromptKind::NewSecret => self.create_secret(&name),
            PromptKind::NewKey => self.add_key(&name),
            PromptKind::DeleteSecret => self.delete_secret_metadata(&name),
            PromptKind::DestroyVersion => {}
        }
    }

    fn delete_secret_metadata(&mut self, name: &str) {
        let key = CacheKey {
            mount: self.secrets_engine.clone(),
            path: self.secrets_path.join(&SecretPath::new(name)),
        };
        self.spawn_delete_secret_metadata(key);
    }

    fn destroy_version(&mut self, name: &str, expected: &str) {
        if name.trim() != expected {
            self.prompt = Some(PromptState {
                kind: PromptKind::DestroyVersion,
                input: String::new(),
                error: Some("typed value does not match required version".to_owned()),
                expected: Some(expected.to_owned()),
            });
            return;
        }
        let Some(version) = expected.parse::<u64>().ok() else {
            return;
        };
        let Some(versions) = &self.versions else {
            return;
        };
        let key = CacheKey {
            mount: self.secrets_engine.clone(),
            path: versions.key.clone(),
        };
        self.spawn_destroy_version(key, version);
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
                expected: None,
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

fn caps_has(caps: &[String], capability: &str) -> bool {
    caps.iter().any(|entry| entry == capability)
}

fn caps_has_root(caps: &[String]) -> bool {
    caps_has(caps, "root")
}

fn caps_allow_create(caps: &[String]) -> bool {
    caps_has_root(caps) || caps_has(caps, "create")
}

fn caps_allow_update(caps: &[String]) -> bool {
    caps_has_root(caps) || caps_has(caps, "update")
}

fn caps_allow_delete(caps: &[String]) -> bool {
    caps_has_root(caps) || caps_has(caps, "delete")
}

fn caps_allow_soft_delete(caps: &[String]) -> bool {
    caps_has_root(caps) || caps_has(caps, "update")
}

fn caps_allow_destroy(caps: &[String]) -> bool {
    caps_has_root(caps) || caps_has(caps, "update")
}

fn caps_allow_undelete(caps: &[String]) -> bool {
    caps_has_root(caps) || caps_has(caps, "update")
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
    use crate::model::{KvMetadata, KvVersionHistory, VersionMeta};
    use crate::vault::VaultApi;

    #[derive(Debug)]
    struct FakeVault {
        engines: Vec<SecretEntry>,
        listings: Mutex<HashMap<(SecretPath, SecretPath), Vec<SecretEntry>>>,
        data: Mutex<HashMap<(SecretPath, SecretPath), KvData>>,
        writes: Mutex<Vec<WriteRecord>>,
        deletes: Mutex<Vec<(SecretPath, SecretPath)>>,
        metadata: Mutex<HashMap<(SecretPath, SecretPath), KvVersionHistory>>,
        version_reads: Mutex<Vec<(SecretPath, SecretPath, u64)>>,
        version_data: Mutex<HashMap<(SecretPath, SecretPath, u64), KvData>>,
        version_deletes: Mutex<Vec<(SecretPath, SecretPath, u64)>>,
        version_undeletes: Mutex<Vec<(SecretPath, SecretPath, u64)>>,
        version_destroys: Mutex<Vec<(SecretPath, SecretPath, u64)>>,
        writable_all: bool,
    }

    type WriteRecord = (SecretPath, SecretPath, BTreeMap<String, String>);

    impl Default for FakeVault {
        fn default() -> Self {
            Self {
                engines: Vec::new(),
                listings: Mutex::new(HashMap::new()),
                data: Mutex::new(HashMap::new()),
                writes: Mutex::new(Vec::new()),
                deletes: Mutex::new(Vec::new()),
                metadata: Mutex::new(HashMap::new()),
                version_reads: Mutex::new(Vec::new()),
                version_data: Mutex::new(HashMap::new()),
                version_deletes: Mutex::new(Vec::new()),
                version_undeletes: Mutex::new(Vec::new()),
                version_destroys: Mutex::new(Vec::new()),
                writable_all: true,
            }
        }
    }

    impl FakeVault {
        fn seeded() -> Arc<Self> {
            let vault = Arc::new(Self {
                engines: vec![SecretEntry::leaf("secret")],
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
            vault.insert_metadata(
                SecretPath::new("secret"),
                SecretPath::new("team/api"),
                KvVersionHistory {
                    current_version: 3,
                    versions: vec![
                        VersionMeta {
                            version: 3,
                            created_time: "2026-10-13T10:00:00Z".to_owned(),
                            deletion_time: None,
                            destroyed: false,
                            is_current: true,
                        },
                        VersionMeta {
                            version: 2,
                            created_time: "2026-10-12T10:00:00Z".to_owned(),
                            deletion_time: Some("2026-10-12T11:00:00Z".to_owned()),
                            destroyed: false,
                            is_current: false,
                        },
                        VersionMeta {
                            version: 1,
                            created_time: "2026-10-11T10:00:00Z".to_owned(),
                            deletion_time: None,
                            destroyed: true,
                            is_current: false,
                        },
                    ],
                },
            );
            vault.insert_version_data(
                SecretPath::new("secret"),
                SecretPath::new("team/api"),
                3,
                kv_data("v3"),
            );
            vault.insert_version_data(
                SecretPath::new("secret"),
                SecretPath::new("team/api"),
                2,
                kv_data("v2"),
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

        fn insert_metadata(&self, mount: SecretPath, path: SecretPath, history: KvVersionHistory) {
            self.metadata
                .lock()
                .expect("metadata lock")
                .insert((mount, path), history);
        }

        fn insert_version_data(
            &self,
            mount: SecretPath,
            path: SecretPath,
            version: u64,
            data: KvData,
        ) {
            self.version_data
                .lock()
                .expect("version data lock")
                .insert((mount, path, version), data);
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

        fn read_kv_metadata(
            &self,
            mount: &SecretPath,
            path: &SecretPath,
        ) -> impl Future<Output = Result<KvVersionHistory, VaultError>> + Send {
            async move {
                self.metadata
                    .lock()
                    .expect("metadata lock")
                    .get(&(mount.clone(), path.clone()))
                    .cloned()
                    .ok_or_else(|| VaultError::Api {
                        status: 404,
                        path: path.as_str().to_owned(),
                        detail: "missing".to_owned(),
                    })
            }
        }

        fn read_kv_version(
            &self,
            mount: &SecretPath,
            path: &SecretPath,
            version: u64,
        ) -> impl Future<Output = Result<KvData, VaultError>> + Send {
            async move {
                self.version_reads
                    .lock()
                    .expect("version reads lock")
                    .push((mount.clone(), path.clone(), version));
                self.version_data
                    .lock()
                    .expect("version data lock")
                    .get(&(mount.clone(), path.clone(), version))
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

        fn delete_kv_secret_version(
            &self,
            mount: &SecretPath,
            path: &SecretPath,
            version: u64,
        ) -> impl Future<Output = Result<(), VaultError>> + Send {
            async move {
                self.version_deletes
                    .lock()
                    .expect("version deletes lock")
                    .push((mount.clone(), path.clone(), version));
                Ok(())
            }
        }

        fn undelete_kv_secret_version(
            &self,
            mount: &SecretPath,
            path: &SecretPath,
            version: u64,
        ) -> impl Future<Output = Result<(), VaultError>> + Send {
            async move {
                self.version_undeletes
                    .lock()
                    .expect("version undeletes lock")
                    .push((mount.clone(), path.clone(), version));
                Ok(())
            }
        }

        fn destroy_kv_secret_version(
            &self,
            mount: &SecretPath,
            path: &SecretPath,
            version: u64,
        ) -> impl Future<Output = Result<(), VaultError>> + Send {
            async move {
                self.version_destroys
                    .lock()
                    .expect("version destroys lock")
                    .push((mount.clone(), path.clone(), version));
                Ok(())
            }
        }

        fn read_token_info(&self) -> impl Future<Output = Result<TokenInfo, VaultError>> + Send {
            async move {
                Ok(TokenInfo {
                    policies: vec!["root".to_owned()],
                    expire_time: None,
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
                deletion_time: None,
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

    fn versions_fixture(path: &str) -> VersionsUi {
        VersionsUi {
            key: SecretPath::new(path),
            current_version: 3,
            versions: vec![
                VersionMeta {
                    version: 3,
                    created_time: "2026-10-13T10:00:00Z".to_owned(),
                    deletion_time: None,
                    destroyed: false,
                    is_current: true,
                },
                VersionMeta {
                    version: 2,
                    created_time: "2026-10-12T10:00:00Z".to_owned(),
                    deletion_time: Some("2026-10-12T11:00:00Z".to_owned()),
                    destroyed: false,
                    is_current: false,
                },
                VersionMeta {
                    version: 1,
                    created_time: "2026-10-11T10:00:00Z".to_owned(),
                    deletion_time: None,
                    destroyed: true,
                    is_current: false,
                },
            ],
            selected: 0,
            preview: None,
        }
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
        app.can_create = false;

        // When: `n` is pressed.
        app.handle_input(key(KeyCode::Char('n')));

        // Then: no prompt opens and a permission error is shown.
        assert_eq!(app.prompt, None);
        assert_eq!(app.status.as_ref().map(|s| s.kind), Some(StatusKind::Error));
    }

    #[test]
    fn new_secret_prompt_opens_and_edits_with_chars() {
        // Given: a writable token in the secrets view.
        let (mut app, _rx, _vault) = test_app();
        app.state = AppState::Main(Mode::Secrets);
        app.can_create = true;

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
        app.can_create = true;

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
        app.can_update = true;

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
        app.can_update = true;

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
        app.can_metadata_delete = false;

        // When: `D` is pressed on a leaf.
        app.handle_input(key(KeyCode::Char(keys::METADATA_DELETE)));

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
        app.can_metadata_delete = true;
        app.apply(Msg::SecretsLoaded {
            generation: 0,
            key: app.current_secrets_key(),
            entries: vec![SecretEntry::dir("team/"), SecretEntry::leaf("root")],
        });
        app.secrets_selected = 0;

        // When: `D` is pressed on the root listing where a directory is first.
        app.handle_input(key(KeyCode::Char(keys::METADATA_DELETE)));

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
        app.can_metadata_delete = true;
        app.apply(Msg::SecretsLoaded {
            generation: 0,
            key: app.current_secrets_key(),
            entries: vec![SecretEntry::leaf("creds")],
        });
        app.secrets_selected = 0;

        // When: `D` opens the confirmation and Enter confirms it.
        app.handle_input(key(KeyCode::Char(keys::METADATA_DELETE)));
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

    #[tokio::test]
    async fn secret_data_v_opens_versions_and_spawns_metadata_load() {
        let (mut app, mut rx, _vault) = test_app();
        app.state = AppState::Main(Mode::SecretData);
        app.secrets_engine = SecretPath::new("secret");
        app.secret_data = Some(SecretDataUi {
            key: SecretPath::new("team/api"),
            data: kv_data("old"),
            selected: 0,
            mode: DataMode::ListOnly,
            original_data: kv_data("old").data,
        });

        app.handle_input(key(KeyCode::Char(keys::VERSIONS)));

        let msg = rx.recv().await.expect("message");
        assert!(matches!(msg, Msg::VersionsLoaded { .. }));
    }

    #[test]
    fn versions_escape_returns_to_secret_data() {
        let (mut app, _rx, _vault) = test_app();
        app.state = AppState::Main(Mode::Versions);
        app.versions = Some(versions_fixture("team/api"));

        app.handle_input(key(KeyCode::Esc));

        assert_eq!(app.state, AppState::Main(Mode::SecretData));
    }

    #[tokio::test]
    async fn versions_enter_loads_selected_version_preview() {
        let (mut app, mut rx, _vault) = test_app();
        app.state = AppState::Main(Mode::Versions);
        app.secrets_engine = SecretPath::new("secret");
        app.versions = Some(versions_fixture("team/api"));

        app.handle_input(key(KeyCode::Enter));

        let msg = rx.recv().await.expect("message");
        assert!(matches!(msg, Msg::SecretVersionLoaded { version: 3, .. }));
    }

    #[tokio::test]
    async fn versions_restore_reads_version_and_writes_new_latest() {
        let (mut app, mut rx, vault) = test_app();
        app.state = AppState::Main(Mode::Versions);
        app.secrets_engine = SecretPath::new("secret");
        app.can_update = true;
        app.versions = Some(versions_fixture("team/api"));

        app.handle_input(key(KeyCode::Char(keys::RESTORE)));

        let msg = rx.recv().await.expect("message");
        assert!(matches!(
            msg,
            Msg::SecretVersionRestored {
                source_version: 3,
                ..
            }
        ));
        let reads = vault.version_reads.lock().expect("reads lock").clone();
        assert!(reads.iter().any(|(m, p, v)| {
            m == &SecretPath::new("secret") && p == &SecretPath::new("team/api") && *v == 3
        }));
        let writes = vault.writes();
        assert!(writes.iter().any(|(m, p, data)| {
            m == &SecretPath::new("secret")
                && p == &SecretPath::new("team/api")
                && data.get("password").is_some_and(|value| value == "v3")
        }));
    }

    #[tokio::test]
    async fn versions_undelete_reloads_versions_after_success() {
        let (mut app, mut rx, _vault) = test_app();
        app.state = AppState::Main(Mode::Versions);
        app.secrets_engine = SecretPath::new("secret");
        app.can_undelete = true;
        let mut versions = versions_fixture("team/api");
        versions.selected = 1;
        app.versions = Some(versions);

        app.handle_input(key(KeyCode::Char(keys::UNDELETE)));

        let msg = rx.recv().await.expect("undelete message");
        app.apply(msg);
        let reload = rx.recv().await.expect("reload message");
        assert!(matches!(reload, Msg::VersionsLoaded { .. }));
    }

    #[tokio::test]
    async fn versions_destroy_prompt_requires_exact_version_text() {
        let (mut app, mut rx, _vault) = test_app();
        app.state = AppState::Main(Mode::Versions);
        app.secrets_engine = SecretPath::new("secret");
        app.can_destroy = true;
        app.versions = Some(versions_fixture("team/api"));

        app.handle_input(key(KeyCode::Char(keys::DESTROY)));
        app.handle_input(key(KeyCode::Char('2')));
        app.handle_input(key(KeyCode::Enter));

        assert_eq!(
            app.prompt
                .as_ref()
                .and_then(|prompt| prompt.error.as_deref()),
            Some("typed value does not match required version")
        );

        app.handle_input(key(KeyCode::Char('3')));
        app.handle_input(key(KeyCode::Enter));
        let msg = rx.recv().await.expect("destroy message");
        assert!(matches!(
            msg,
            Msg::SecretVersionDestroyed { version: 3, .. }
        ));
    }

    #[tokio::test]
    async fn secret_data_d_soft_deletes_latest_without_evicting_parent_listing() {
        let (mut app, mut rx, _vault) = test_app();
        app.state = AppState::Main(Mode::SecretData);
        app.secrets_engine = SecretPath::new("secret");
        app.can_soft_delete = true;
        app.secrets_path = SecretPath::new("team/");
        app.secret_data = Some(SecretDataUi {
            key: SecretPath::new("team/api"),
            data: kv_data("old"),
            selected: 0,
            mode: DataMode::ListOnly,
            original_data: kv_data("old").data,
        });
        let generation = app.store.bump_generation();
        let parent = CacheKey {
            mount: SecretPath::new("secret"),
            path: SecretPath::new("team/"),
        };
        app.apply(Msg::SecretsLoaded {
            generation,
            key: parent.clone(),
            entries: vec![SecretEntry::leaf("api")],
        });

        app.handle_input(key(KeyCode::Char('d')));

        let msg = rx.recv().await.expect("delete message");
        app.apply(msg);
        assert_eq!(
            app.store.secrets(&parent),
            Some([SecretEntry::leaf("api")].as_slice())
        );
    }

    #[tokio::test]
    async fn secrets_upper_d_metadata_delete_reloads_parent_listing() {
        let (mut app, mut rx, _vault) = test_app();
        app.state = AppState::Main(Mode::Secrets);
        app.secrets_engine = SecretPath::new("secret");
        app.secrets_path = SecretPath::new("team/");
        app.can_metadata_delete = true;
        app.apply(Msg::SecretsLoaded {
            generation: 0,
            key: app.current_secrets_key(),
            entries: vec![SecretEntry::leaf("api")],
        });
        app.secrets_selected = 0;

        app.handle_input(key(KeyCode::Char(keys::METADATA_DELETE)));
        app.handle_input(key(KeyCode::Enter));

        let msg = rx.recv().await.expect("delete message");
        app.apply(msg);
        let reload = rx.recv().await.expect("reload message");
        assert!(matches!(reload, Msg::SecretsLoaded { .. }));
    }

    #[test]
    fn capabilities_message_updates_create_update_soft_delete_metadata_delete_destroy_flags() {
        let (mut app, _rx, _vault) = test_app();
        let generation = app.store.bump_generation();

        app.apply(Msg::Capabilities {
            generation,
            create: true,
            update: false,
            soft_delete: true,
            metadata_delete: false,
            destroy: true,
            undelete: true,
        });

        assert!(app.can_create);
        assert!(!app.can_update);
        assert!(app.can_soft_delete);
        assert!(!app.can_metadata_delete);
        assert!(app.can_destroy);
        assert!(app.can_undelete);
    }

    #[test]
    fn stale_versions_loaded_message_is_dropped_by_generation() {
        let (mut app, _rx, _vault) = test_app();
        let generation = app.store.bump_generation();

        app.apply(Msg::VersionsLoaded {
            generation: generation.saturating_sub(1),
            key: CacheKey {
                mount: SecretPath::new("secret"),
                path: SecretPath::new("team/api"),
            },
            history: KvVersionHistory {
                current_version: 3,
                versions: Vec::new(),
            },
        });

        assert!(app.versions.is_none());
    }

    #[test]
    fn stale_versions_loaded_with_matching_secret_data_does_not_open_versions_mode() {
        let (mut app, _rx, _vault) = test_app();
        app.state = AppState::Main(Mode::SecretData);
        app.secret_data = Some(SecretDataUi {
            key: SecretPath::new("team/api"),
            data: kv_data("old"),
            selected: 0,
            mode: DataMode::ListOnly,
            original_data: kv_data("old").data,
        });
        let current = app.store.bump_generation();

        app.apply(Msg::VersionsLoaded {
            generation: current.saturating_sub(1),
            key: CacheKey {
                mount: SecretPath::new("secret"),
                path: SecretPath::new("team/api"),
            },
            history: KvVersionHistory {
                current_version: 3,
                versions: Vec::new(),
            },
        });

        assert_eq!(app.state, AppState::Main(Mode::SecretData));
        assert!(app.versions.is_none());
    }

    #[test]
    fn stale_path_not_found_does_not_clear_state() {
        let (mut app, _rx, _vault) = test_app();
        app.state = AppState::Main(Mode::Versions);
        app.secret_data = Some(SecretDataUi {
            key: SecretPath::new("team/api"),
            data: kv_data("old"),
            selected: 0,
            mode: DataMode::ListOnly,
            original_data: kv_data("old").data,
        });
        app.versions = Some(versions_fixture("team/api"));
        let current = app.store.bump_generation();

        app.apply(Msg::PathNotFound {
            generation: current.saturating_sub(1),
            key: CacheKey {
                mount: SecretPath::new("secret"),
                path: SecretPath::new("team/api"),
            },
        });

        assert_eq!(app.state, AppState::Main(Mode::Versions));
        assert!(app.secret_data.is_some());
        assert!(app.versions.is_some());
    }

    #[tokio::test]
    async fn stale_secret_version_deleted_does_not_spawn_reload() {
        let (mut app, mut rx, _vault) = test_app();
        let current = app.store.bump_generation();

        app.apply(Msg::SecretVersionDeleted {
            generation: current.saturating_sub(1),
            key: CacheKey {
                mount: SecretPath::new("secret"),
                path: SecretPath::new("team/api"),
            },
            version: 3,
        });

        let received = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;
        assert!(received.is_err());
    }

    #[test]
    fn versions_selection_change_clears_preview() {
        let (mut app, _rx, _vault) = test_app();
        app.state = AppState::Main(Mode::Versions);
        let mut versions = versions_fixture("team/api");
        versions.preview = Some(VersionPreviewUi {
            data: kv_data("v3"),
            version: 3,
            selected: 0,
            mode: DataMode::ListOnly,
        });
        app.versions = Some(versions);

        app.handle_input(key(KeyCode::Down));

        assert!(
            app.versions
                .as_ref()
                .and_then(|v| v.preview.as_ref())
                .is_none()
        );
    }

    #[test]
    fn stale_preview_response_for_previous_selection_is_ignored() {
        let (mut app, _rx, _vault) = test_app();
        app.state = AppState::Main(Mode::Versions);
        app.secrets_engine = SecretPath::new("secret");
        let mut versions = versions_fixture("team/api");
        versions.selected = 1;
        app.versions = Some(versions);
        let generation = app.store.bump_generation();

        app.apply(Msg::SecretVersionLoaded {
            generation,
            key: CacheKey {
                mount: SecretPath::new("secret"),
                path: SecretPath::new("team/api"),
            },
            version: 3,
            data: kv_data("v3"),
        });

        assert!(
            app.versions
                .as_ref()
                .and_then(|v| v.preview.as_ref())
                .is_none()
        );
    }

    #[tokio::test]
    async fn version_preview_read_404_reports_failure_without_path_not_found() {
        let (mut app, mut rx, vault) = test_app();
        app.state = AppState::Main(Mode::Versions);
        app.secrets_engine = SecretPath::new("secret");
        app.versions = Some(versions_fixture("team/api"));
        vault
            .version_data
            .lock()
            .expect("version data lock")
            .remove(&(SecretPath::new("secret"), SecretPath::new("team/api"), 3));

        app.handle_input(key(KeyCode::Enter));

        let msg = rx.recv().await.expect("message");
        assert!(matches!(msg, Msg::Failure { .. }));
        app.apply(msg);
        assert!(app.secret_data.is_none());
        assert_eq!(app.state, AppState::Main(Mode::Versions));
    }

    #[test]
    fn undelete_non_deleted_version_shows_info_and_skips_request() {
        let (mut app, _rx, vault) = test_app();
        app.state = AppState::Main(Mode::Versions);
        app.secrets_engine = SecretPath::new("secret");
        app.can_undelete = true;
        app.versions = Some(versions_fixture("team/api"));

        app.handle_input(key(KeyCode::Char(keys::UNDELETE)));

        assert_eq!(
            app.status.as_ref().map(|status| status.text.as_str()),
            Some("version 3 is not deleted")
        );
        assert!(
            vault
                .version_undeletes
                .lock()
                .expect("undeletes lock")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn versions_restore_reloads_history_with_current_generation() {
        let (mut app, mut rx, _vault) = test_app();
        app.state = AppState::Main(Mode::Versions);
        app.secrets_engine = SecretPath::new("secret");
        app.versions = Some(versions_fixture("team/api"));
        let key = CacheKey {
            mount: SecretPath::new("secret"),
            path: SecretPath::new("team/api"),
        };
        let generation = app.store.generation();

        app.apply(Msg::SecretVersionRestored {
            generation,
            key,
            source_version: 2,
        });

        let msg = rx.recv().await.expect("versions reload");
        assert!(matches!(msg, Msg::VersionsLoaded { .. }));
        assert_eq!(msg.generation(), app.store.generation());
    }

    #[tokio::test]
    async fn open_versions_uses_shared_generation_for_capabilities_message() {
        let (mut app, mut rx, _vault) = test_app();
        app.state = AppState::Main(Mode::SecretData);
        app.secrets_engine = SecretPath::new("secret");
        app.secret_data = Some(SecretDataUi {
            key: SecretPath::new("team/api"),
            data: kv_data("old"),
            selected: 0,
            mode: DataMode::ListOnly,
            original_data: kv_data("old").data,
        });

        app.handle_input(key(KeyCode::Char(keys::VERSIONS)));

        let first = rx.recv().await.expect("first message");
        let second = rx.recv().await.expect("second message");
        let generation_of = |msg: &Msg| msg.generation();

        assert_eq!(generation_of(&first), generation_of(&second));
    }

    #[test]
    fn leaving_secret_data_resets_permissions() {
        let (mut app, _rx, _vault) = test_app();
        app.state = AppState::Main(Mode::SecretData);
        app.can_create = true;
        app.can_update = true;
        app.can_soft_delete = true;
        app.can_metadata_delete = true;
        app.can_destroy = true;
        app.can_undelete = true;

        app.handle_input(key(KeyCode::Esc));

        assert_eq!(app.state, AppState::Main(Mode::Secrets));
        assert!(!app.can_create);
        assert!(!app.can_update);
        assert!(!app.can_soft_delete);
        assert!(!app.can_metadata_delete);
        assert!(!app.can_destroy);
        assert!(!app.can_undelete);
    }

    #[test]
    fn destroy_prompt_empty_input_shows_typed_value_error() {
        let (mut app, _rx, _vault) = test_app();
        app.prompt = Some(PromptState {
            kind: PromptKind::DestroyVersion,
            input: String::new(),
            error: None,
            expected: Some("3".to_owned()),
        });

        app.handle_input(key(KeyCode::Enter));

        assert_eq!(
            app.prompt
                .as_ref()
                .and_then(|prompt| prompt.error.as_deref()),
            Some("typed value does not match required version")
        );
    }
}
