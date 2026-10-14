# tresor

[![ci](https://github.com/njoerd114/tresor/actions/workflows/ci.yml/badge.svg)](https://github.com/njoerd114/tresor/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)


A k9s-style terminal UI for HashiCorp Vault, rewritten in Rust.

This is a from-scratch Rust reimplementation of [vaultview](https://github.com/njoerd114/vaultview)
(the Go/tview original), built the way [sofka](https://sofka.rs) reimplements k9s:
`ratatui` + `crossterm` + `tokio`, an async-first event loop, a single `Mode` state
machine, and an in-memory store folded by generation-tagged messages. Currently
supports **KV2 secret engines only** (same as the Go version).

## Features

- List all secret engines
- Hierarchical secret browser with per-path caching
- Named connection **profiles** (`~/.config/tresor/config.toml`), switchable at
  runtime with the k9s-style `:ctx` palette
- `/` fuzzy filter over the focused list (engines, secrets, keys) with a live
  match count in the command bar
- `<x>` reveal secret value (preview pane)
- `<e>` edit secret value (inline textarea), `Ctrl+S` save
- `<c>` copy secret value to the system clipboard
- `<v>` open version history from secret-data view
- Version pane actions: `Enter` preview, `r` restore, `u` undelete, `X` destroy (typed confirmation)
- Secret-data action: `d` soft-delete latest version
- `Ctrl+R` hard reload of the current path (with 404 backtrack)
- Token inspector (`:token`): `lookup-self` details, renew-self, and child-token
  creation (policies + TTL + use limit) — the minted token is shown once and copyable
- Response wrapping: `:unwrap` a wrapping token into a pretty-printed payload, or
  `:wrap` a JSON payload with an optional TTL
- `:policies` browses ACL policies with a read-only preview pane
- `<e>` authors/edits a policy in your `$EDITOR` (never an in-TUI editor), `<n>` creates one
- Vault header: address, sealed state, version, token policies/expiry
- Config modal when `VAULT_ADDR`/`VAULT_TOKEN` are missing
- Color-coded status line (errors/errors/info/success, auto-clear after 5s)

### Scope

tresor is deliberately a **browser, not an admin console**. The operations it leaves to the
`vault` / `bao` CLI (PKI issuance, dynamic-secret leases, HA/seal/unseal, policy & auth
configuration, bulk destructive operations, in-TUI full-screen editors, secret sync) are
tracked with their reasoning in [`docs/out-of-scope.md`](docs/out-of-scope.md).

## Keybindings

| Key | Action |
|---|---|
| `:` | command palette — `:ctx` switch profile, `:filter`, `:quit` |
| `/` | fuzzy filter the focused list (`Esc` clears) |
| `Enter` | select / drill down / open secret |
| `Esc` | back one level / cancel |
| `↑ ↓` / `j k` | move selection |
| `Tab` | next key (secret data view) |
| `:` | open the command bar (`:policies` opens the ACL policy browser) |
| `x` | reveal secret value |
| `e` | edit secret value; in the policies view, edit the selected policy in `$EDITOR` |
| `c` | copy secret value |
<<<<<<< HEAD
| `v` | open versions (secret-data view) |
| `n` | new secret (secrets view, when permitted) |
| `D` | metadata-delete secret — with confirmation (secrets view, when permitted) |
| `d` | soft-delete latest secret version (secret-data view, when permitted) |
| `Enter` | preview selected version (versions view) |
| `r` | restore selected version as latest (versions view, when permitted) |
| `u` | undelete selected soft-deleted version (versions view, when permitted) |
| `X` | destroy selected version — typed confirmation (versions view, when permitted) |
=======
| `n` | new secret / new policy (when permitted) |
| `d` | delete secret — with confirmation (secrets view, when permitted) |
>>>>>>> origin/main
| `a` | add key to the open secret (when permitted) |
| `Ctrl+S` | save edits |
| `Ctrl+R` | hard refresh current path |
| `:` | command palette (`token`, `t`, `unwrap`, `u`, `wrap`, `w`) |
| `r` | renew the active token (token inspector) |
| `n` | create a child token (token inspector, when permitted) |
| `w` | wrap a JSON payload (token inspector, when permitted) |
| `u` | unwrap a wrapping token (token inspector) |
| `c` | copy the shown token/payload (token inspector) |
| `Ctrl+C` | quit |

## Policies

Open the ACL policy browser with the `:policies` command (`:` opens the command
bar at the bottom of the screen). The left pane lists every ACL policy
(`GET sys/policies/acl`, with a `GET ?list=true` fallback for gateways that
reject the `LIST` verb); the right pane previews the selected policy's HCL text
read-only. Policy text that Vault returns `base64:`-prefixed is decoded for
display.

Editing never happens inside the TUI: `<e>` suspends the interface and hands the
policy to `$EDITOR` (`$VISUAL` first, then `$EDITOR`), then reads the result back.
If the text changed you get a confirmation prompt before `<Enter>` `PUT`s it to
`sys/policies/acl/{name}`. `<n>` authors a brand-new policy the same way. The
edit action is **capability-gated**: tresor probes `sys/policies/acl/{name}` and
only offers it when your token holds `create`, `update`, or `root` there.

## Install

### macOS & Linux — Homebrew

```bash
brew install njoerd114/tresor/tresor
```

### Cargo (any platform with a Rust toolchain)

```bash
cargo install --git https://github.com/njoerd114/tresor
# once published to crates.io:  cargo install tresor
```

### Prebuilt binaries (Releases)

Every release attaches binaries for all targets. Pick yours, unpack, put it on `PATH`:

```bash
# example: linux x86_64
curl -LO https://github.com/njoerd114/tresor/releases/latest/download/tresor-x86_64-unknown-linux-gnu.tar.gz
tar xzf tresor-x86_64-unknown-linux-gnu.tar.gz
install -m755 tresor-x86_64-unknown-linux-gnu ~/.local/bin/tresor
```

Targets: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
`x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`.

### Linux distro packages (attached to each release)

```bash
# Debian / Ubuntu (apt / dpkg)
curl -LO .../download/vX.Y.Z/tresor_X.Y.Z_linux_amd64.deb && sudo dpkg -i tresor_*.deb

# Fedora / RHEL / openSUSE (dnf / yum / zypper)
sudo rpm -i tresor_X.Y.Z_linux_amd64.rpm      # or: sudo dnf install ./tresor_*.rpm

# Alpine (apk)
sudo apk add --allow-untrusted tresor_X.Y.Z_linux_amd64.apk
```

The `.deb` / `.rpm` / `.apk` files are built with [nfpm](https://nfpm.goreleaser.com) —
see the package job in `.github/workflows/release.yaml`. Dedicated APT/YUM/zypper
repositories can be added later; today the packages live on the GitHub Release.

### Arch Linux (yay / AUR)

A `PKGBUILD` ships in the repository; build it locally today:

```bash
git clone https://github.com/njoerd114/tresor && cd tresor
yay -Bi packaging/aur          # or: makepkg -si in packaging/aur
```

AUR publication (`yay -S tresor`) is a maintainer step, not automated yet.

### Windows

```powershell
# scoop (manifest ships in the repo; add it to a bucket to get `scoop install tresor`)
scoop install https://raw.githubusercontent.com/njoerd114/tresor/main/packaging/scoop/tresor.json
```

Or download `tresor-x86_64-pc-windows-msvc.zip` from the latest Release and put
`tresor.exe` on your `PATH`. `winget` packaging can be added later.

## Build from source

```bash
git clone https://github.com/njoerd114/tresor && cd tresor
cargo build --release --locked        # -> target/release/tresor
```

Requirements: stable Rust (edition 2024, ≥ 1.85); the `fmt` check also needs nightly
(`rustup toolchain install nightly --component rustfmt`).

Verify your build the way CI does:

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo +nightly fmt --all -- --check
cargo machete && cargo deny check
```

Run it against a throwaway Vault or OpenBao:

```bash
scripts/dev-vault.sh                  # starts `vault server -dev` + seed KV2 data
VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root ./target/release/tresor
```

Without env vars the app opens a configuration modal to enter address + token.

## OpenBao

Works with [OpenBao](https://openbao.org) (the OSS fork of Vault) out of the box.
Config sources, in precedence order (mirroring the `bao` CLI):

1. `BAO_ADDR` / `BAO_TOKEN` (a set-even-empty `BAO_*` wins over `VAULT_*`)
2. `VAULT_ADDR` / `VAULT_TOKEN`
3. Token file: `BAO_TOKEN_PATH` → `VAULT_TOKEN_PATH` → `~/.vault-token`

So a session from `bao login -method=oidc role=...` is picked up automatically:

```bash
bao login -method=oidc role=platform-engineers   # writes ~/.vault-token
./target/release/tresor                        # reads BAO_ADDR + ~/.vault-token
```

(`BAO_ADDR` must be exported — the CLI doesn't persist it.) The KV2 mount
works unmodified; `sys/health` and KV2 list/read are parsed leniently because
OpenBao response variants emit `null` (or omit) fields HashiCorp Vault sends
as `""` (e.g. `performance_standby`, metadata `deletion_time`) — the same
tolerance the Go version's json decoder has.

### Diagnosing connection problems

```bash
./target/release/tresor --check
```

Prints a plain-text report (health, token, engines, per-engine KV2 list),
exits non-zero on the first failure — the screenshot-free way to report a
problem (paste the output instead of a status-line photo).

Create/edit commands are **permission-aware**: the app probes
`sys/capabilities-self` for the current path and only lists `n new secret` /
`a add key` (and allows the actions) when your token can `create`/`update`
there. Attempting them without permission shows a clear status error.

## Profiles & contexts

Define named connection profiles in `~/.config/tresor/config.toml` (or
`$TRESOR_CONFIG/config.toml`). A profile names an address and points at a token
**file** or a token **command** — raw tokens are never stored inline:

```toml
current = "dev"

[profiles.dev]
addr = "http://127.0.0.1:8200"
token_file = "~/.vault-token"

[profiles.prod]
addr = "https://vault.example:8200"
token_command = "pass show vault/prod-token"
```

- `current` (optional) is the profile used at startup when no `BAO_*`/`VAULT_*`
  environment config is present.
- `token_file` is read and trimmed (`~` expands to the home directory).
- `token_command` runs through the shell (`sh -c` / `cmd /C`) with a 10s
  timeout; its trimmed stdout is the token. **Config files are executable trust
  boundaries** — only point `token_command` at commands you trust.
- A profile with both or neither token source, an inline `token = "..."`, or an
  empty `addr` is skipped with a warning.

Startup precedence: environment config (`BAO_*`/`VAULT_*`) → `current` profile →
the configuration modal. Press `:` and run `ctx` to switch profiles at runtime;
the picker is type-to-filter and marks the connected profile with `●`.

## Theme

The default palette matches **sofka.rs**'s default skin (catppuccin-mocha).
If a sofka config is present it is reused automatically:

- `~/.config/sofka/config.toml` plus sorted `conf.d/*.toml` drop-ins
  (or `$SOFKA_CONFIG` for a different config directory)
- `[skin] name = "..."` selects a bundled skin —
  `catppuccin-{mocha,latte,frappe,macchiato}`, `gruvbox-dark` (aliases like
  `mocha` accepted); unknown skins fall back to mocha with a warning
- `[skin.colors]` per-swatch hex overrides (`red`, `teal`, `surface0`, …)
  are applied on top

A missing, empty, or unparsable config simply falls back to the bundled
default — it never breaks startup.

## Local dev Vault

```bash
scripts/dev-vault.sh           # starts `vault server -dev` (token: root) + seeds KV2 data
scripts/dev-vault.sh stop      # stops it
```

Seed data (idempotent): `secret/apps/web/db-creds`, `secret/apps/web/api-key`,
`secret/infra/tls`, `secret/creds`.

## Tests

```bash
cargo test                     # unit + insta golden snapshots + wiremock vault-client integration
cargo nextest run              # (if installed) faster runner
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
cargo machete                  # unused-dependency check
```

The Vault client is tested at the wire level with `wiremock` (a fake Vault HTTP API),
and every ratatui view has insta golden-frame snapshots (`TestBackend`, 100×20).

## Architecture

```
src/
├── main.rs        # tokio + crossterm event loop: EventStream + Msg channel + 1s tick, select!
├── app.rs         # App<V: VaultApi>: Mode state machine, input dispatch, model builders, draw
├── vault/         # VaultApi trait (native async fn), VaultClient over vaultrs (KV2)
├── store.rs       # in-memory cache + generation-tagged Msg folding (stale-drop)
├── state.rs       # Mode + ViewStack (breadcrumb navigation)
├── model.rs       # boundary-parsed types (SecretEntry, KvData, TokenInfo, HealthInfo)
├── path.rs        # SecretPath newtype (trailing-slash semantics)
├── profiles.rs    # named connection profiles (token file/command) from config.toml
├── fuzzy.rs       # fuzzy matching (command palette, profile picker, list filter)
├── ui/            # pure view renderers: header, engines, secrets, secret_data, modal,
│                  #   prompt, palette, contexts
├── theme.rs       # semantic color palette
├── clipboard.rs   # copypasta + pbcopy-wl-copy fallback
└── event.rs       # Command enum
```

The UI never blocks on the network: vault calls run as spawned tasks that push
generation-tagged `Msg` values over an `mpsc` channel; stale responses are dropped
by the store (the sofka pattern).

## Credits

- Inspired by **k9s** (the Kubernetes TUI) and reimagined the way
  **[sofka](https://sofka.rs)** — a Rust k8s TUI — reimagines it: `ratatui` +
  `tokio`, async-first event loop, `Msg`-over-`mpsc` with generation tags.
- Works with **[OpenBao](https://openbao.org)** (the open-source fork of
  HashiCorp Vault) as well as HashiCorp Vault itself.
- UX vocabulary follows the `vault kv` / `bao kv` CLIs.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or the
[MIT license](LICENSE-MIT), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
