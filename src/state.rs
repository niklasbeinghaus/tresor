//! UI mode and breadcrumb navigation state.

use crate::constants::pages;

/// The single UI mode. Exactly one view is visible at a time.
#[allow(
    clippy::exhaustive_enums,
    reason = "closed UI state machine; exhaustive matches are required by the app architecture"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Vault address/token configuration form.
    Config,
    /// Secret engines list.
    Engines,
    /// Hierarchical KV2 secret browser.
    Secrets,
    /// Secret key/value detail view.
    SecretData,
    /// Token inspector (lookup-self, renew-self, child tokens, wrapping).
    Token,
}

impl Mode {
    /// Returns the stable router page identifier for this mode.
    #[must_use]
    pub const fn page_id(&self) -> &'static str {
        match self {
            Self::Config => pages::CONFIG,
            Self::Engines => pages::ENGINES,
            Self::Secrets => pages::SECRETS,
            Self::SecretData => pages::SECRET_DATA,
            Self::Token => pages::TOKEN,
        }
    }
}

/// Breadcrumb stack for one-visible-page navigation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewStack(Vec<Mode>);

impl Default for ViewStack {
    fn default() -> Self {
        Self::new()
    }
}

impl ViewStack {
    /// Builds a navigation stack rooted at the post-configuration engines page.
    #[must_use]
    pub fn new() -> Self {
        Self::with_root(Mode::Engines)
    }

    /// Builds a navigation stack rooted at `root`.
    #[must_use]
    pub fn with_root(root: Mode) -> Self {
        Self(vec![root])
    }

    /// Pushes a drill-down mode onto the breadcrumb stack.
    pub fn push(&mut self, mode: Mode) {
        self.0.push(mode);
    }

    /// Pops one breadcrumb level, keeping the root entry when already at root.
    pub fn pop(&mut self) -> Mode {
        if self.0.len() > 1 {
            self.0.pop();
        }
        self.current()
    }

    /// Returns the currently visible mode.
    #[must_use]
    pub fn current(&self) -> Mode {
        self.0.last().copied().unwrap_or(Mode::Engines)
    }

    /// Returns the root mode of this navigation stack.
    #[must_use]
    pub fn root(&self) -> Mode {
        self.0.first().copied().unwrap_or(Mode::Engines)
    }

    /// Returns the number of breadcrumb entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true when the stack has no breadcrumb entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Replaces the currently visible mode without changing the breadcrumb depth.
    pub fn replace_top(&mut self, mode: Mode) {
        match self.0.last_mut() {
            Some(top) => *top = mode,
            None => self.0.push(mode),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Mode, ViewStack};
    use crate::constants::pages;

    #[test]
    fn page_id_when_mode_maps_to_router_id() {
        assert_eq!(Mode::Config.page_id(), pages::CONFIG);
        assert_eq!(Mode::Engines.page_id(), pages::ENGINES);
        assert_eq!(Mode::Secrets.page_id(), pages::SECRETS);
        assert_eq!(Mode::SecretData.page_id(), pages::SECRET_DATA);
        assert_eq!(Mode::Token.page_id(), pages::TOKEN);
    }

    #[test]
    fn stack_starts_at_engines_by_default() {
        let stack = ViewStack::new();

        assert_eq!(stack.root(), Mode::Engines);
        assert_eq!(stack.current(), Mode::Engines);
        assert_eq!(stack.len(), 1);
        assert!(!stack.is_empty());
    }

    #[test]
    fn stack_can_start_at_config() {
        let stack = ViewStack::with_root(Mode::Config);

        assert_eq!(stack.root(), Mode::Config);
        assert_eq!(stack.current(), Mode::Config);
        assert_eq!(stack.len(), 1);
    }

    #[test]
    fn push_then_pop_tracks_current_mode() {
        let mut stack = ViewStack::new();

        stack.push(Mode::Secrets);
        stack.push(Mode::SecretData);
        assert_eq!(stack.current(), Mode::SecretData);
        assert_eq!(stack.len(), 3);

        assert_eq!(stack.pop(), Mode::Secrets);
        assert_eq!(stack.current(), Mode::Secrets);
        assert_eq!(stack.len(), 2);

        assert_eq!(stack.pop(), Mode::Engines);
        assert_eq!(stack.current(), Mode::Engines);
        assert_eq!(stack.len(), 1);
    }

    #[test]
    fn pop_when_at_root_keeps_root() {
        let mut engines = ViewStack::new();
        let mut config = ViewStack::with_root(Mode::Config);

        assert_eq!(engines.pop(), Mode::Engines);
        assert_eq!(engines.current(), Mode::Engines);
        assert_eq!(engines.len(), 1);

        assert_eq!(config.pop(), Mode::Config);
        assert_eq!(config.current(), Mode::Config);
        assert_eq!(config.len(), 1);
    }

    #[test]
    fn replace_top_changes_current_without_changing_root() {
        let mut stack = ViewStack::new();

        stack.push(Mode::Secrets);
        stack.replace_top(Mode::SecretData);

        assert_eq!(stack.root(), Mode::Engines);
        assert_eq!(stack.current(), Mode::SecretData);
        assert_eq!(stack.len(), 2);
    }
}
