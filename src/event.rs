//! Typed internal commands consumed by the app event loop.

/// Commands the UI can perform, independent of terminal input events.
#[allow(
    clippy::exhaustive_enums,
    reason = "closed command set; input dispatch and app handling must match exhaustively"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Connect, load engines, and hydrate header state.
    Init,
    /// Drill into a directory, open secret data, or submit a modal.
    Select,
    /// Navigate one level up.
    Back,
    /// Reveal the selected secret value.
    Reveal,
    /// Edit the selected secret value.
    Edit,
    /// Copy the selected secret value.
    Copy,
    /// Save edited secret data.
    Save,
    /// Clear the current path cache and reload it.
    HardRefresh,
    /// Move focus to the next key in the secret data view.
    NextKey,
    /// Exit the application.
    Quit,
}

#[cfg(test)]
mod tests {
    use super::Command;

    #[test]
    fn commands_are_cloneable_and_equatable() {
        let command = Command::HardRefresh;
        let cloned = command;

        assert_eq!(cloned, Command::HardRefresh);
        assert_ne!(cloned, Command::Quit);
    }
}
