//! tresor — a `k9s`-style terminal UI for `HashiCorp` Vault and `OpenBao`.
//!
//! Architecture mirrors sofka (a Rust reimplementation of k9s): ratatui + crossterm +
//! tokio, an async-first event loop, a single `Mode` enum driving the UI, a
//! generation-tagged `Msg` channel from background vault tasks, and a small in-memory
//! `Store` that the renderer folds into.

pub mod app;
pub mod clipboard;
pub mod config;
pub mod constants;
pub mod editor;
pub mod event;
pub mod model;
pub mod path;
pub mod sofka;
pub mod state;
pub mod store;
#[cfg(test)]
pub mod test_support;
pub mod theme;
pub mod ui;
pub mod vault;
