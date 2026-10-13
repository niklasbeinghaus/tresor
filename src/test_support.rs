//! Test-only helpers shared across modules.

use std::sync::{Mutex, MutexGuard};

/// Serializes tests that mutate the process environment.
///
/// Environment mutation is process-global: per-module locks are not enough,
/// because two modules' env tests can still interleave under the default
/// parallel test harness (which is why `std::env::set_var` is `unsafe` in
/// Rust 2024). Every env-mutating test must hold this single lock.
pub fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
