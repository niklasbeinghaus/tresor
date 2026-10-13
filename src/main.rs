//! tresor binary — tokio/crossterm terminal event loop.

use std::io::stdout;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use crossterm::event::{
    DisableMouseCapture, EnableMouseCapture, Event, EventStream, KeyCode, KeyEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use futures::StreamExt as _;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use secrecy::ExposeSecret as _;
use tokio::time;
use tresor::app::{App, AppState};
use tresor::config::Config;
use tresor::path::SecretPath;
use tresor::theme::Theme;
use tresor::vault::{VaultApi as _, VaultClient};

#[tokio::main]
async fn main() -> Result<()> {
    // Default to our crate's own events only; third-party crates (rustify,
    // vaultrs, hyper, rustls) log noisy errors over the `log` bridge that would
    // smear into the alternate screen. RUST_LOG overrides.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("tresor=warn,off"));
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .init();

    match std::env::args().nth(1).as_deref() {
        Some("--check") => {
            return run_check(Config::from_env().context(
                "no configuration: set BAO_ADDR (or VAULT_ADDR) and provide a token \
                 (BAO_TOKEN/VAULT_TOKEN env or the ~/.vault-token written by `bao login`)",
            )?)
            .await;
        }
        Some("--version" | "-V") => {
            print_version();
            return Ok(());
        }
        Some("--help" | "-h") => {
            print_help();
            return Ok(());
        }
        _ => {}
    }

    let env_config = Config::from_env();
    let startup_config = env_config
        .clone()
        .unwrap_or_else(|| Config::new("http://127.0.0.1:8200", ""));
    let vault = Arc::new(
        VaultClient::connect(&startup_config.addr, startup_config.token.expose_secret())
            .context("failed to initialize Vault client")?,
    );
    let theme = Theme::load_sofka_or_default();
    let (mut app, mut msg_rx) = match env_config {
        Some(config) => App::new_with_theme(config, vault, theme),
        None => App::config_input_with_theme(vault, theme),
    };
    if !matches!(app.state, AppState::ConfigInput) {
        app.spawn_initial_loads();
    }

    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        default_hook(info);
    }));

    enable_raw_mode().context("failed to enable raw mode")?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen, EnableMouseCapture)
        .context("failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend).context("failed to create terminal")?;
    let mut events = EventStream::new();
    let mut tick = time::interval(Duration::from_secs(1));
    let mut dirty = true;
    let mut quit = false;

    while !quit {
        if dirty {
            terminal
                .draw(|frame| app.draw(frame, frame.area()))
                .context("failed to draw terminal")?;
            dirty = false;
        }

        tokio::select! {
            maybe_event = events.next() => {
                if let Some(event) = maybe_event {
                    let event = event.context("failed to read terminal event")?;
                    if let Event::Key(key) = event {
                        if key.kind == KeyEventKind::Press {
                            if matches!(app.state, AppState::ConfigInput) && key.code == KeyCode::Enter {
                                let config = app.modal_config();
                                match VaultClient::connect(&config.addr, config.token.expose_secret()) {
                                    Ok(vault) => app.connect_config(config, Arc::new(vault)),
                                    Err(err) => app.set_modal_error(err.message()),
                                }
                            } else {
                                quit = app.handle_input(key);
                            }
                            dirty = true;
                        }
                    }
                } else {
                    quit = true;
                }
            }
            maybe_msg = msg_rx.recv() => {
                if let Some(msg) = maybe_msg {
                    app.apply(msg);
                    dirty = true;
                }
            }
            _instant = tick.tick() => {
                app.expire_status();
                dirty = true;
            }
        }
    }

    restore_terminal();
    Ok(())
}

#[allow(
    clippy::print_stdout,
    reason = "CLI surface; stdout is the report channel"
)]
fn print_version() {
    println!("tresor {}", env!("CARGO_PKG_VERSION"));
}

#[allow(
    clippy::print_stdout,
    reason = "CLI surface; stdout is the report channel"
)]
fn print_help() {
    println!(
        "tresor {} — a k9s-style TUI for HashiCorp Vault and OpenBao

USAGE:
  tresor             run the TUI
  tresor --check     connectivity/API diagnostic (health, token, engines, KV2 list)
  tresor --version   print the version
  tresor --help      print this help

CONFIGURATION (first match wins):
  BAO_ADDR / VAULT_ADDR              Vault or OpenBao address
  BAO_TOKEN / VAULT_TOKEN            authentication token
  BAO_TOKEN_PATH / VAULT_TOKEN_PATH  CLI token store override
  ~/.vault-token                     written by `vault login` / `bao login`",
        env!("CARGO_PKG_VERSION")
    );
}

fn restore_terminal() {
    if let Err(err) = disable_raw_mode() {
        tracing::warn!(%err, "failed to disable raw mode");
    }
    let mut out = stdout();
    if let Err(err) = execute!(out, LeaveAlternateScreen, DisableMouseCapture) {
        tracing::warn!(%err, "failed to restore terminal screen");
    }
}

/// Prints a plain-text connectivity/API diagnostic (health, token, engines,
/// per-engine KV2 list) and fails fast on the first error — the screenshot-free
/// retest and debugging path (`tresor --check`).
#[allow(
    clippy::print_stdout,
    reason = "diagnostic CLI surface; stdout is the report channel"
)]
async fn run_check(config: Config) -> Result<()> {
    let vault = VaultClient::connect(&config.addr, config.token.expose_secret())
        .context("failed to initialize Vault client")?;
    println!("addr: {}", config.addr);

    match vault.sys_health().await {
        Ok(health) => println!(
            "health: OK (sealed: {}, vault: {})",
            health.sealed, health.version
        ),
        Err(err) => return check_error("health", &err),
    }

    match vault.read_token_info().await {
        Ok(info) => {
            let eternal = if info.is_eternal() { ", eternal" } else { "" };
            println!(
                "token: OK (policies: {}{})",
                info.policies.join(", "),
                eternal
            );
        }
        Err(err) => return check_error("token", &err),
    }

    let engines = match vault.read_secret_engines().await {
        Ok(engines) => {
            println!("engines: {} mounts", engines.len());
            engines
        }
        Err(err) => return check_error("engines", &err),
    };

    for engine in &engines {
        match vault
            .list_kv_secrets(&engine.name, &SecretPath::root())
            .await
        {
            Ok(entries) => println!("  list {}: OK ({} keys)", engine.name, entries.len()),
            Err(tresor::vault::VaultError::Api { status: 404, .. }) => {
                println!("  list {}: not KV2 (skipped)", engine.name);
            }
            Err(err) => return check_error(&format!("list {}", engine.name), &err),
        }
    }
    Ok(())
}

fn check_error(step: &str, err: &tresor::vault::VaultError) -> Result<()> {
    Err(anyhow::anyhow!("{step}: FAILED — {}", err.message()))
}
