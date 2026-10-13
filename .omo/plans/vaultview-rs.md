# vaultview-rs — Rust Rewrite of vaultview (k9s-style Vault TUI)

**Status:** Approved scope. Decision-complete. Ready for execution.
**Reference blueprint:** sofka (github.com/nklmilojevic/sofka) — a k9s reimplementation in Rust on ratatui+tokio+kube-rs. We mirror its architecture for HashiCorp Vault.

## GOAL

A new Rust binary crate `vaultview-rs` (git repo at `/Users/niklas.beinghaus/github.com/njoerd114/vaultview-rs`, new `main` branch, no remote yet) that is **feature-parity** with the Go vaultview (17 files, ~1.5k LOC) and matches sofka-grade architecture quality. Full TDD including UI render (golden) tests. Verification against a local `vault server -dev` instance with seeded KV2 data.

## STACK (pinned, verified 2026-10-13)

| Purpose | Crate | Notes |
|---|---|---|
| TUI | `ratatui` 0.30 | TestBackend for golden tests |
| Terminal backend | `crossterm` 0.29 | `event-stream` feature |
| Async runtime | `tokio` 1.x | multi_thread, worker_threads=4 |
| Vault client | `vaultrs` 0.8 | KV2 list/read/write/read_metadata; auth token lookup; sys health — **ALL VERIFIED PRESENT in 0.8.0 source**: `kv2::{list,read,read_metadata,set}`, `token::lookup_self`, `sys::health`, `sys::mount::list` (HashMap<String,MountResponse> for engines). No raw-reqwest fallback needed |
| Textarea (edit mode) | `tui-textarea` 0.7 | verify crossterm version compat with ratatui 0.30 |
| Clipboard | `copypasta` 0.10 | macOS: works in Terminal.app/iTerm2; `pbcopy` fallback wrapper |
| Errors | `anyhow` (app) + `thiserror` (lib errors) | |
| Serialization | `serde` + `serde_json` | boundary types |
| Time | `jiff` | RFC3339 timestamps from Vault metadata |
| CLI | `clap` 4 derive | `--version`, `--addr`, `--token` override env |
| Logging | `tracing` + `tracing-subscriber` | |
| Secrets | `secrecy` | token + secret values wrap `SecretString` |
| Tests | `cargo-nextest` + `insta` + `proptest` + `wiremock` | wiremock = wire-level fake Vault HTTP API (less-mock principle) |

Strict Cargo config from programming skill (`cargo-strict.md`): `[lints]` (deny `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `todo`, `unimplemented`; pedantic+nursery warn), release profile (lto=fat, panic=abort), `rustfmt.toml` (max_width=100), `clippy.toml`, `deny.toml`. No `unsafe` anywhere (no miri gate needed).

## FEATURE PARITY (from Go app, hard requirements)

1. **Init/config:** read `VAULT_ADDR` + `VAULT_TOKEN` env; if either missing → **config modal** (two input fields: addr, token; token masked). OK → connect + main UI; Cancel → exit.
2. **Header bar:** logo/wordmark + info table (VaultViewRev, VaultRev, VaultAddr, Sealed, TokenPolicies, TokenExpirationTime) + right-side status line (Err/Warn/Info/Success colors), auto-clear after 5s.
3. **Secret engines view:** list mounted engines (KV2 assumed, like Go), Enter → secrets view for that engine.
4. **Secrets view (hierarchical browser):** engine root lists KV2 paths (dirs end `/`); Enter on dir → drill down — with **cache per (engine,path)**; Enter on leaf → secret data view; Esc/Escape → one level up (breadcrumb stack); `Ctrl+R` → hard refresh of current path — on 404, remove child from parent cache + backtrack (mirror Go `secretsHardRefresh`); path + engine shown in view title.
5. **Secret data view:** list of key names (values masked with `*****` by default). Keys: `x` = reveal value in right pane, `c` = copy selected key's value to clipboard, `e` = edit selected value in textarea pane, `Ctrl+S` = save (write back only if changed — detect via hash compare of original vs edited values), `Tab` = move to next key, `Esc` = back to list. View title shows Secret name, version, created_time.
6. **Page switching semantics:** one visible view at a time; Mode enum + navigation stack (sofka breadcrumb pattern).

## ARCHITECTURE (mirrors sofka, lite)

```
src/
├── main.rs           # clap, tracing init, terminal setup, tokio::select! event loop
├── app.rs            # App struct: current Mode, view stack, VaultClient, Store, status line
├── event.rs          # UI event plumbing: from crossterm EventStream → App commands (Msg enum)
├── state.rs          # Mode enum + ViewStack (breadcrumb); exhaustive-match friendly
├── store.rs          # secret/mount cache: HashMap<CacheKey, Vec<SecretEntry>> + generation tags (stale-drop)
├── config.rs         # env (+ clap override) → typed Config; parse-at-boundary
├── constants.rs      # keybindings (x/e/c, Ctrl+S/R, Tab, Esc), view names, NAValue, Mask
├── path.rs           # SecretPath newtype (trailing-slash semantics) + parent/child utils
├── theme.rs          # palette + semantic styles
├── clipboard.rs      # copypasta wrapper + pbcopy fallback
├── vault/
│   ├── mod.rs        # VaultApi trait (async fn in trait, Send+Sync) + VaultError (thiserror)
│   └── client.rs     # vaultrs-backed impl
└── ui/
    ├── mod.rs        # draw dispatch: match Mode → view renderer
    ├── header.rs     # logo + info table + status line widget
    ├── engines.rs    # engines view renderer
    ├── secrets.rs    # secrets browser renderer
    ├── secret_data.rs# key/value view renderer (list + reveal pane + textarea)
    └── modal.rs      # config modal renderer
```

### Core types (contracts for parallel work)

```rust
// vault/mod.rs
pub enum VaultError { Connection(String), Api { status: u16, path: String, detail: String }, Parse(String) }
pub struct SecretEntry { pub name: SecretPath, pub is_dir: bool }        // parsed at boundary
pub struct KvData { pub data: BTreeMap<String, SecretString>, pub metadata: KvMetadata }
pub struct KvMetadata { pub version: u64, pub created_time: Option<jiff::Timestamp>, pub destroyed: Option<bool> }
pub struct TokenInfo { pub policies: Vec<String>, pub expire_time: Option<jiff::Timestamp> }
pub struct HealthInfo { pub version: String, pub sealed: Option<bool> }

#[async_trait] // native `async fn` in trait, Rust 2024 — no async_trait crate needed
pub trait VaultApi: Send + Sync {
    async fn read_secret_engines(&self) -> Result<Vec<SecretEntry>, VaultError>;
    async fn list_kv_secrets(&self, mount: &SecretPath, path: &SecretPath) -> Result<Vec<SecretEntry>, VaultError>;
    async fn read_kv_secret(&self, mount: &SecretPath, path: &SecretPath) -> Result<KvData, VaultError>;
    async fn write_kv_secret(&self, mount: &SecretPath, path: &SecretPath, data: &BTreeMap<String, String>) -> Result<(), VaultError>;
    async fn read_token_info(&self) -> Result<TokenInfo, VaultError>;
    async fn sys_health(&self) -> Result<HealthInfo, VaultError>;
}
```

```rust
// state.rs
pub enum Mode { Config, Engines, Secrets, SecretData }  // + MainPage/ModalPage analog
pub struct ViewStack(Vec<Mode>);                        // push/pop; pop-to-root rules per view

// store.rs
#[derive(Clone, PartialEq, Eq, Hash)] pub struct CacheKey { pub mount: SecretPath, pub path: SecretPath }
pub struct Store { pub engines: Vec<SecretEntry>, pub secrets: HashMap<CacheKey, Vec<SecretEntry>>, pub generation: u64 }
impl Store { fn apply<'a>(&mut self, msg: Msg) -> Option<ActionResult>; }  // generation-tagged stale-drop
pub enum Msg { EnginesLoaded{generation, entries}, SecretsLoaded{generation, key, entries},
               SecretLoaded{generation, key, data: KvData}, HardRefreshDone{generation, key},
               PathNotFound{generation, key}, Error{generation, message} }
```

### Event loop (main.rs, mirroring sofka)

```
loop { tokio::select! {
    Some(Ok(event)) = crossterm event stream.next() => { app.handle_input(event)?; dirty = true }
    Some(event) = app.commands.recv()          => { app.handle_command(event); batch try_recv; dirty = true }
    _ = tick.tick()                            => { app.expire_status(); dirty = true }
} if dirty { ui::draw(terminal, &mut app)?; dirty = false } }
```
- UI never blocks: every vault call runs in `tokio::spawn`ed task hitting `VaultApi`, result sent back via `mpsc` `Msg`/command enum.
- On view transition (Enter/back): if cache miss → spawn load task; show stale/spinner meanwhile.

## KEYBINDINGS (parity with Go; mode-scoped dispatch in app.handler)

| Key | Mode | Action |
|---|---|---|
| Enter | Engines/Secrets | drill down / open secret data |
| Esc/`q`? — Go has none; keep Esc | Secrets/SecretData/Modal | back one level / cancel |
| `x` | SecretData | reveal value |
| `c` | SecretData | copy value to clipboard |
| `e` | SecretData | open edit textarea |
| Ctrl+S | SecretData | save if changed |
| Ctrl+R | Secrets | hard refresh (surrender cache for path) |
| Tab | SecretData | next key |
| Ctrl+C | any | quit (terminal cleanup) |

## TEST PLAN (TDD — red → green → refactor; Given/When/Then)

| Layer | Technique | Coverage |
|---|---|---|
| **Unit** | plain `#[test]` + `proptest` | `path.rs` (parent/child round-trip, trailing-slash property), `config.rs` parsing (env/missing/clap-override), `state.rs` ViewStack push/pop/root rules, `store.rs` generation stale-drop + cache semantics, secret-data change detection (hash compare), status auto-expiry (injected clock), keybinding dispatch table |
| **Integration (wire)** | `wiremock` mock Vault HTTP API | vault client: engines list, kv list/read/write, token lookup, sys/health — request shape (paths incl. trailing slash, `X-Vault-Token` header), response parse, error status mapping (404 → PathNotFound, 403) |
| **UI golden** | `ratatui::backend::TestBackend` + `insta` snapshot | header, engines view, secrets view (empty/dirs/leaf), secret data view (masked/revealed/editor), config modal — fixed 120×30 frame, determinism mandated (BTreeMap + injected time) |
| **E2E** | binary vs dev vault (`scripts/dev-vault.sh`): `vault server -dev` + seeded KV2; tmux-driven keystrokes script capturing output frames | happy path: engines → browse dir → reveal value → copy → edit → save → verify via `vault kv get`; error path: open deleted secret → 404 backtrack |

CI gate (local, final wave): `cargo fmt --check` (nightly) → `cargo clippy --all-targets --all-features -- -D warnings` → `cargo nextest run` → `cargo machete` → `cargo deny check` (if installed; else note) → `.snap.new` absence check.

## IMPLEMENTATION ORDER

- **Wave 0 (me, now):** strict `Cargo.toml` (+lints, profiles), `rustfmt.toml`, `clippy.toml`, `deny.toml`, `.gitignore`, `rust-toolchain.toml`, skeleton module dirs; first commit.
- **Wave 1 (parallel, 3 agents):**
  1. `path` + `config` + `constants` + `clipboard` + unit tests
  2. `state` + `store` + `event Msg` + unit/proptest tests
  3. `vault` module (trait + vaultrs impl + verify API surface) + wiremock integration tests; `scripts/dev-vault.sh` + seed script
- **Wave 2 (parallel, 2 agents):** `ui/` views (header/engines/secrets/secret_data/modal) + theme — with golden tests landing together with renderers.
- **Wave 3 (1 agent):** `main.rs` event loop + `app.rs` orchestration + input dispatch; wire everything; smoke run.
- **Wave 4 (me):** quality gates, README, new-repo `AGENTS.md`, manual E2E against dev vault, final commit.

## DONE = (definition of done)

- [ ] `cargo build --release` clean; binary boots to modal when env missing
- [ ] `cargo nextest run` all green (unit+integration+golden)
- [ ] Manual E2E against `scripts/dev-vault.sh` seeded vault: browse, reveal, copy, edit, save, hard-refresh, 404 backtrack — verified via tmux frames + `vault kv get`
- [ ] clippy `-D warnings`, fmt clean, machete clean
- [ ] Runtime ≤3 workers, no `unwrap`/`panic`/`indexing` outside tests, no `unsafe`

## RISKS / OPEN ITEMS

- ~~`vaultrs` 0.8 API surface~~ **RESOLVED 2026-10-13**: verified in crate source — `kv2::{list,read,read_metadata,set}`, `token::lookup_self`, `sys::health`, `sys::mount::list` all exist. Wave 1 agent #3 must still confirm exact response structs (`ReadHealthResponse`, `LookupTokenResponse`, `MountResponse`, `KvV2ReadResponse`) and field names.
- `tui-textarea` 0.7 ↔ crossterm version alignment with ratatui — Wave 2 agent pins exact versions.
- copypasta on macOS SSH sessions fails → clipboard.rs falls back to `pbcopy`/`pbpaste`; golden tests mock the Clipboard trait.
- Sealed state: Go shows Sealed only when set; keep `Option<bool>` semantics in HealthInfo.