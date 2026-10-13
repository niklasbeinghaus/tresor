# PROJECT KNOWLEDGE BASE

**Generated:** 2026-10-13
**Repo:** vaultview-rs (Rust rewrite of the Go vaultview TUI)

## OVERVIEW
Rust TUI for HashiCorp Vault and OpenBao — a k9s-style terminal UI (~3k LOC, 18 crates in `src/`). Stack: `ratatui` 0.29 + `crossterm` 0.28 + `tokio` 1.x + `vaultrs` 0.8 (+ `reqwest` for the lenient health probe). Architecture mirrors sofka (Rust k9s): async-first `select!` event loop, single `Mode` enum, `Msg`-over-`mpsc` with generation tags, small in-memory `Store`. **KV2 secret engines only.**

## STRUCTURE
```
src/
├── main.rs        # tokio + crossterm loop: EventStream | Msg rx | 1s tick → draw
├── app.rs         # App<V: VaultApi>: mode dispatch, model builders, draw (LARGE — split candidate)
├── lib.rs         # module wiring
├── vault/         # VaultApi trait (native async fn, no async-trait) + vaultrs impl + VaultError
├── store.rs       # Store (engines/secrets cache) + Msg enum + generation stale-drop
├── state.rs       # Mode + ViewStack breadcrumb
├── event.rs       # Command enum (pure; dispatch lives in app.rs)
├── model.rs       # boundary types: SecretEntry, KvData, KvMetadata, TokenInfo, HealthInfo
├── path.rs        # SecretPath newtype — trailing-slash dir semantics (parity with Go utils)
├── config.rs      # Config {addr, token}; BAO_*→VAULT_* env chain + CLI token file (~/.vault-token)
├── clipboard.rs   # TextClipboard trait + copypasta + CommandClipboard (pbcopy/xclip/wl-copy)
├── theme.rs       # semantic palette + sofka skins (catppuccin/gruvbox); default = sofka mocha
├── sofka.rs       # reuses ~/.config/sofka config [skin] (name + color overrides), graceful fallback
└── ui/            # PURE renderers: header, engines, secrets, secret_data, modal (+ insta snapshots)
tests/vault_integration.rs  # wiremock wire-level tests of VaultClient
scripts/dev-vault.sh + seed-vault.sh  # local `vault server -dev` + KV2 seed data
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Add key handling | `app.rs` `handle_*_input` per mode | keys from `constants::keys` |
| Change a view | `src/ui/<view>.rs` | model struct + `draw_*` pure fn; update its insta snapshot |
| Add a vault call | `vault/mod.rs` trait + `vault/client.rs` impl | map wire types → `model.rs` types at the boundary |
| App state transitions | `app.rs` `apply()` + `open_selected_secret_entry` etc. | Msg folding → store + state |
| Background loads | `app.rs` `spawn_load_*` helpers | `Arc<V>` clone + generation + `Msgs` over mpsc |
| Colors | `theme.rs` | never inline colors in views |

## CONVENTIONS
- `App<V: VaultApi>` is generic over the vault client so tests inject a fake (Bounded polymorphism). **Never use `Box<dyn VaultApi>`** — native async fn in trait is not dyn-safe.
- Every vault call in a spawned task is wrapped in `tokio::time::timeout(30s)`; errors travel as `Msg::Failure` → status line (never UI panics).
- UI status: `set_status(kind, msg)`; expires after `constants::STATUS_EXPIRY_SECS` via the 1s tick (`expire_status`).
- Secret values are `secrecy::SecretString` end to end; list rows always render `constants::MASK`; reveal is an explicit user action in the preview pane.
- Views are pure: state lives in App, renderers draw from model structs built by `App::*_model()`. No ratatui state widgets (no `ListState`); selection is a usize in App, clipping manual.
- `draw()` header is `Constraint::Length(5)` — do NOT shrink: the status row needs its 3rd inner row (a shorter area silently clips the status line).
- `d` (secrets view) deletes via KV2 **metadata delete** (`DELETE {mount}/metadata/{path}`)
  — removes the secret from listings; dirs are virtual (rejected with a hint).
  A confirmation prompt (`PromptKind::DeleteSecret`) guards it; `raw_request`
  tolerates the 204 empty-body response.
- Write commands are capability-gated: `spawn_capabilities` probes `sys/capabilities-self`
  for the current data path (a synthetic name under directories, the exact path for
  open secrets) and only enables `n new secret` / `a add key` when `create`/`update`
  (or `root`) is present. Probing shares the load task's generation — never bump in
  the probe or the list result is dropped as stale.
- In `SecretData` the `x/e/c/a` lookup keys are only intercepted OUTSIDE the editor;
  inside it they are literal text (`inside_secret_editor()`), so values containing
  those letters edit correctly.
- Error paths: `Msg::PathNotFound` evicts the dead entry from the parent cache listing; a failed secret read while in `SecretData` backs out to `Secrets` (Go parity).
- Tracing filter in `main.rs` defaults to `tresor=debug,off` — rustify/vaultrs log noisy errors over the `log` bridge that smear the TUI screen.
- Theme: default = sofka's catppuccin-mocha; `sofka.rs` parses `~/.config/sofka/config.toml` + `conf.d/*.toml` (`[skin] name` + `[skin.colors]` overrides; `$SOFKA_CONFIG` supported). Bundled skins: catppuccin-{mocha,latte,frappe,macchiato}, gruvbox-dark; anything else → mocha + warn. Never fails startup.
- `sys::health`, `list_kv_secrets`, and `read_kv_secret` are **raw reqwest calls** (`X-Vault-Token`, envelope parsed via `raw_json` helper, lenient field reads) — NOT `vaultrs::sys::health`/`kv2::list`/typed reads. Reason: OpenBao/Vault response variants use `null` for fields HashiCorp Vault sends as `""` (`performance_standby`, metadata `deletion_time`, ...); strict serde rejects `null` for `String` while Go's json decoder tolerates it. Do not "simplify" back to strict vaultrs calls. `vaultrs` is still used for `sys::mount::list` and `auth/token/lookup-self` (both verified envelope-stable).
- `list_kv_secrets` uses the LIST verb with a **GET `?list=true` fallback on 400/403/405** — production gateways have been observed rejecting LIST over HTTP/1.1; keep the fallback, it is not dead code. `reqwest` must keep `http2` + compression features for the same reason.
- `raw_json` reads the body as **text first** and parses after: an error status with a non-JSON body (e.g. a gateway's `text/plain` 400) becomes `VaultError::Api` with the raw text as detail — never a misleading "error decoding response body" parse error.
- Config env semantics mirror the `bao` CLI: a set-even-empty `BAO_*` var beats `VAULT_*`; token falls back to `BAO_TOKEN_PATH` → `VAULT_TOKEN_PATH` → `~/.vault-token` (what `bao login` writes). Token file read is `read_first_token` (trimmed, first non-empty).

## ANTI-PATTERNS (THIS PROJECT)
- **No async-trait, no `Box<dyn VaultApi>`** (object-safety). Use generics.
- **No `unwrap`/`expect`/`panic`/`indexing` in prod code** — strict lints deny them; `rows[i]` must be destructured via slice patterns.
- **Do not soften the Cargo lints** (`-D warnings` gate): `missing_docs`, `doc_markdown` (backtick `CamelCase`/snake_case in docs), `exhaustive_structs/enums` allowed project-wide (bin+lib same package).
- `ratatui`/`crossterm` are pinned to 0.29/0.28 — **tui-textarea 0.7 requires them**; upgrading ratatui to 0.30 silently breaks widget type compatibility.
- Don't touch Cargo.toml deps without running `cargo machete` (unused-dep gate).
- No `serde` derive needed (client maps manually); `serde_json::Value` only at the vault boundary.

## COMMANDS
```bash
cargo run                    # dev (needs VAULT_ADDR/VAULT_TOKEN, else modal)
tresor --check            # CLI diagnostic: health/token/engines/per-engine list, exit≠0 on failure
cargo test                   # 80+ tests (unit + insta golden + wiremock)
cargo nextest run            # faster
cargo clippy --all-targets -- -D warnings   # zero-tolerance gate
cargo fmt --all -- --check
cargo machete
cargo-deny check             # advisories/bans/licenses/sources
INSTA_UPDATE=always cargo test --lib ui::<view>  # refresh golden snapshots
scripts/dev-vault.sh [stop]  # local dev vault + seed; then run with root/#root token
```

## NOTES
- Golden snapshots live in `src/ui/snapshots/` + `src/snapshots/`; CI fails on pending `.snap.new`.
- `app.rs` is ~1.4k lines (dispatch + spawns + model builders + tests) — above the 250-LOC guideline; accepted for now (orchestrator with in-file unit tests), prime split target: `app/` module (input/tasks/models).
- Public repo: `github.com/njoerd114/tresor` (remote `origin`). Dual-licensed MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`); CI + release + dependabot live under `.github/`.
- Go parity quirks preserved: all engines listed unfiltered (KV2 assumed); secrets browsers cache per (mount, path); 404 read shows `secret '<path>' does not exist`.