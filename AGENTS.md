# PROJECT KNOWLEDGE BASE

**Generated:** 2026-10-13
**Repo:** vaultview-rs (Rust rewrite of the Go vaultview TUI)

## OVERVIEW
Rust TUI for HashiCorp Vault and OpenBao — a k9s-style terminal UI (~3.5k LOC, 19 crates in `src/`). Stack: `ratatui` 0.30 + `crossterm` 0.29 + `tokio` 1.x + `vaultrs` 0.8 (+ `reqwest` for the lenient health/policy probes). Architecture mirrors sofka (Rust k9s): async-first `select!` event loop, single `Mode` enum, `Msg`-over-`mpsc` with generation tags, small in-memory `Store`. **KV2 secret engines + ACL policy browsing.**

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
├── model.rs       # boundary types: SecretEntry, KvData, KvMetadata, TokenInfo, MintedToken, WrappedToken, HealthInfo, PolicyEntry, PolicyDocument
├── path.rs        # SecretPath newtype — trailing-slash dir semantics (parity with Go utils)
├── config.rs      # Config {addr, token}; BAO_*→VAULT_* env chain + CLI token file (~/.vault-token)
├── clipboard.rs   # TextClipboard trait + copypasta + CommandClipboard (pbcopy/xclip/wl-copy)
├── editor.rs      # TextEditor trait + CommandTextEditor ($VISUAL→$EDITOR), temp-file handoff
├── theme.rs       # semantic palette + sofka skins (catppuccin/gruvbox); default = sofka mocha
├── sofka.rs       # reuses ~/.config/sofka config [skin] (name + color overrides), graceful fallback
└── ui/            # PURE renderers: header, engines, secrets, secret_data, token, policies, command_line, modal, prompt (+ insta snapshots)
tests/vault_integration.rs  # wiremock wire-level tests of VaultClient
scripts/dev-vault.sh + seed-vault.sh  # local `vault server -dev` + KV2 seed data
scripts/sync-packaging.sh  # release step: regenerates Formula/tresor.rb + scoop/AUR pins from a tag
Formula/tresor.rb          # Homebrew formula (generated from packaging/homebrew/tresor.rb.tmpl)
packaging/                 # scoop manifest + AUR PKGBUILD (pins rewritten by sync-packaging.sh)
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Add key handling | `app.rs` `handle_*_input` per mode | keys from `constants::keys` |
| Change a view | `src/ui/<view>.rs` | model struct + `draw_*` pure fn; update its insta snapshot |
| Add a vault call | `vault/mod.rs` trait + `vault/client.rs` impl | map wire types → `model.rs` types at the boundary |
| App state transitions | `app.rs` `apply()` + `open_selected_secret_entry` etc. | Msg folding → store + state |
| Background loads | `app.rs` `spawn_load_*` helpers | `Arc<V>` clone + generation + `Msgs` over mpsc |
| Policy browsing (`:policies`) | `app.rs` `handle_policies_input` + `ui/policies.rs` | list + read-only preview; edit is capability-gated |
| `$EDITOR` handoff | `editor.rs` + `main.rs` `run_editor_handoff` | App emits `EditorRequest`; `main.rs` owns terminal suspend/restore |
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
- ACL policies: `:policies` (a `:` command bar overlay, not a `Mode`) opens the
  root-level `Mode::Policies` page. List via `GET sys/policies/acl` (LIST verb +
  `GET ?list=true` fallback, like KV), read via `GET sys/policies/acl/{name}` —
  decode a `base64:`-prefixed `policy` field. The view is read-only; editing hands
  off to `$EDITOR` (`$VISUAL` → `$EDITOR`). App emits an `EditorRequest` that
  `main.rs` fulfils (App never touches the terminal: it disables raw mode / leaves
  the alt screen, runs the editor, restores, then recreates the `EventStream`).
  Save is confirmed (`PromptKind::SavePolicy`) before `PUT sys/policies/acl/{name}`.
  Write gating probes `sys/policies/acl/{name}` for `create`/`update`/`root`.
  Policy load and its capability probe share the caller's generation (never
  `bump_generation` in either) so neither is dropped as stale.
- In `SecretData` the `x/e/c/a` lookup keys are only intercepted OUTSIDE the editor;
  inside it they are literal text (`inside_secret_editor()`), so values containing
  those letters edit correctly.
- Token inspector (`:token` / `Mode::Token`): renders `lookup_self` details; `r` renews
  (`auth/token/renew-self`), `n` mints a child token (`auth/token/create`), `w`/`u`
  wrap/unwrap (`sys/wrapping/*`). Child-token and wrap actions are gated by a
  `sys/capabilities-self` probe of `auth/token/create` / `sys/wrapping/wrap`
  (`Msg::TokenCapabilities`); child-token specs are collected by chained prompts
  (policies → TTL → use limit). Minted and wrapping tokens are shown ONCE in the preview
  pane and are never cached or persisted; unwrap pretty-prints the payload.
- Error paths: `Msg::PathNotFound` evicts the dead entry from the parent cache listing; a failed secret read while in `SecretData` backs out to `Secrets` (Go parity).
- Tracing filter in `main.rs` defaults to `tresor=warn,off` — rustify/vaultrs log noisy errors over the `log` bridge that smear the TUI screen.
- Theme: default = sofka's catppuccin-mocha; `sofka.rs` parses `~/.config/sofka/config.toml` + `conf.d/*.toml` (`[skin] name` + `[skin.colors]` overrides; `$SOFKA_CONFIG` supported). Bundled skins: catppuccin-{mocha,latte,frappe,macchiato}, gruvbox-dark; anything else → mocha + warn. Never fails startup.
- `sys::health`, `list_kv_secrets`, and `read_kv_secret` are **raw reqwest calls** (`X-Vault-Token`, envelope parsed via `raw_json` helper, lenient field reads) — NOT `vaultrs::sys::health`/`kv2::list`/typed reads. Reason: OpenBao/Vault response variants use `null` for fields HashiCorp Vault sends as `""` (`performance_standby`, metadata `deletion_time`, ...); strict serde rejects `null` for `String` while Go's json decoder tolerates it. Do not "simplify" back to strict vaultrs calls. `vaultrs` is still used for `sys::mount::list` and `auth/token/lookup-self` (both verified envelope-stable).
- `list_kv_secrets` uses the LIST verb with a **GET `?list=true` fallback on 400/403/405** — production gateways have been observed rejecting LIST over HTTP/1.1; keep the fallback, it is not dead code. `reqwest` must keep `http2` + compression features for the same reason.
- `raw_json` reads the body as **text first** and parses after: an error status with a non-JSON body (e.g. a gateway's `text/plain` 400) becomes `VaultError::Api` with the raw text as detail — never a misleading "error decoding response body" parse error.
- Config env semantics mirror the `bao` CLI: a set-even-empty `BAO_*` var beats `VAULT_*`; token falls back to `BAO_TOKEN_PATH` → `VAULT_TOKEN_PATH` → `~/.vault-token` (what `bao login` writes). Token file read is `read_first_token` (trimmed, first non-empty).

## ANTI-PATTERNS (THIS PROJECT)
- **No async-trait, no `Box<dyn VaultApi>`** (object-safety). Use generics.
- **No `unwrap`/`expect`/`panic`/`indexing` in prod code** — strict lints deny them; `rows[i]` must be destructured via slice patterns.
- **Do not soften the Cargo lints** (`-D warnings` gate): `missing_docs`, `doc_markdown` (backtick `CamelCase`/snake_case in docs), `exhaustive_structs/enums` allowed project-wide (bin+lib same package).
- `ratatui` 0.30 / `crossterm` 0.29. The editor widget is `ratatui-textarea` — the maintained fork of `tui-textarea` 0.7, which is pinned to `ratatui` 0.29 (unmaintained) and must **not** be reintroduced; it would drag in a second `ratatui` and silently break widget type compatibility.
- Don't touch Cargo.toml deps without running `cargo machete` (unused-dep gate).
- No `serde` derive needed (client maps manually); `serde_json::Value` only at the vault boundary.

## COMMANDS
```bash
cargo run                    # dev (needs VAULT_ADDR/VAULT_TOKEN, else modal)
tresor --check            # CLI diagnostic: health/token/engines/per-engine list, exit≠0 on failure
cargo test                   # 130+ tests (unit + insta golden + wiremock)
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
- `app.rs` is ~2.9k lines (dispatch + spawns + model builders + tests) — above the 250-LOC guideline; accepted for now (orchestrator with in-file unit tests), prime split target: `app/` module (input/tasks/models).
- Public repo: `github.com/njoerd114/tresor` (remote `origin`). Dual-licensed MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`); CI + release + dependabot live under `.github/`.
- Go parity quirks preserved: all engines listed unfiltered (KV2 assumed); secrets browsers cache per (mount, path); 404 read shows `secret '<path>' does not exist`.