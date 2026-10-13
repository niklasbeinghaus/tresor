//! Per-view command bar (k9s/sofka style): contextual keybinding hints on the
//! left, current view title on the right. Renderer is stateless — it takes a
//! [`Page`] and the theme, nothing else.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::theme::Theme;

/// The page the command bar describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    /// Vault address/token configuration form.
    Config,
    /// Secret engines list.
    Engines,
    /// Hierarchical secret browser.
    Secrets,
    /// Secret key/value view.
    SecretData,
    /// Token inspector view.
    Token,
}

impl Page {
    /// The view title shown right-aligned on the bar.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Config => "Vault Configuration",
            Self::Engines => "[Secret Engines]",
            Self::Secrets => "Secrets",
            Self::SecretData => "Secret Data",
            Self::Token => "Token Inspector",
        }
    }

    /// The contextual `(key, action)` hint pairs shown on the left. Create/edit
    /// and delete commands are only listed when the token holds the capability.
    #[must_use]
    pub const fn hints(self, permission: Permission) -> &'static [(&'static str, &'static str)] {
        match (self, permission.write, permission.delete) {
            (Self::Config, _, _) => &[("enter", "connect"), ("esc", "quit")],
            (Self::Engines, _, _) => &[("enter", "open"), ("esc", "quit"), ("j/k", "move")],
            (Self::Token, _, _) => token_hints(permission),
            (Self::Secrets, true, true) => &[
                ("enter", "open"),
                ("n", "new secret"),
                ("d", "delete"),
                ("esc", "back"),
                ("^r", "refresh"),
                ("j/k", "move"),
            ],
            (Self::Secrets, true, false) => &[
                ("enter", "open"),
                ("n", "new secret"),
                ("esc", "back"),
                ("^r", "refresh"),
                ("j/k", "move"),
            ],
            (Self::Secrets, false, _) => &[
                ("enter", "open"),
                ("esc", "back"),
                ("^r", "refresh"),
                ("j/k", "move"),
            ],
            (Self::SecretData, true, _) => &[
                ("x", "reveal"),
                ("e", "edit"),
                ("c", "copy"),
                ("a", "add key"),
                ("^s", "save"),
                ("tab", "next"),
                ("esc", "back"),
            ],
            (Self::SecretData, false, _) => &[
                ("x", "reveal"),
                ("e", "edit"),
                ("c", "copy"),
                ("^s", "save"),
                ("tab", "next"),
                ("esc", "back"),
            ],
        }
    }
}

/// What the token may do at the current path (drives which hints are shown).
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent capability flags grouped for command-bar rendering"
)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Permission {
    /// Token may create/update secrets here.
    pub write: bool,
    /// Token may delete secrets here.
    pub delete: bool,
    /// Token may create child tokens.
    pub create_token: bool,
    /// Token may wrap data.
    pub wrap: bool,
}

impl Permission {
    /// No write, delete, or token-management rights (browse-only).
    #[must_use]
    pub const fn read_only() -> Self {
        Self {
            write: false,
            delete: false,
            create_token: false,
            wrap: false,
        }
    }

    /// Full write, delete, and token-management rights.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            write: true,
            delete: true,
            create_token: true,
            wrap: true,
        }
    }
}

/// Token-inspector hints, hiding child-token and wrap actions the token may not perform.
const fn token_hints(permission: Permission) -> &'static [(&'static str, &'static str)] {
    match (permission.create_token, permission.wrap) {
        (true, true) => &[
            ("r", "renew"),
            ("n", "new token"),
            ("w", "wrap"),
            ("u", "unwrap"),
            ("c", "copy"),
            ("esc", "back"),
        ],
        (true, false) => &[
            ("r", "renew"),
            ("n", "new token"),
            ("u", "unwrap"),
            ("c", "copy"),
            ("esc", "back"),
        ],
        (false, true) => &[
            ("r", "renew"),
            ("w", "wrap"),
            ("u", "unwrap"),
            ("c", "copy"),
            ("esc", "back"),
        ],
        (false, false) => &[
            ("r", "renew"),
            ("u", "unwrap"),
            ("c", "copy"),
            ("esc", "back"),
        ],
    }
}

/// Draws the one-row command bar: key hints left, page title right.
pub fn draw_commands(
    frame: &mut Frame<'_>,
    area: Rect,
    page: Page,
    permission: Permission,
    theme: &Theme,
) {
    let mut left = Vec::new();
    let mut left_width = 0usize;
    for (index, (key, action)) in page.hints(permission).iter().enumerate() {
        if index > 0 {
            left.push(Span::raw(" │ "));
            left_width += 3;
        }
        left.push(Span::styled(
            *key,
            Style::default()
                .fg(theme.title)
                .add_modifier(Modifier::BOLD),
        ));
        left.push(Span::raw(format!(" {action}")));
        left_width += key.len() + 1 + action.len();
    }
    let mut spans = left;
    let title = page.title();
    let pad = usize::from(area.width).saturating_sub(left_width + title.len());
    spans.push(Span::raw(" ".repeat(pad)));
    spans.push(Span::styled(
        title,
        Style::default()
            .fg(theme.title)
            .add_modifier(Modifier::BOLD),
    ));
    let line = Line::from(spans);
    frame.render_widget(
        Paragraph::new(line).style(Style::default().bg(theme.selected_bg)),
        area,
    );
}

#[cfg(test)]
mod tests {
    use insta::assert_snapshot;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;

    fn render(width: u16, height: u16, page: Page) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("TestBackend");
        terminal
            .draw(|frame| {
                draw_commands(
                    frame,
                    Rect::new(0, 0, width, height),
                    page,
                    Permission::read_only(),
                    &Theme::default(),
                );
            })
            .expect("draw");
        let buffer = terminal.backend().buffer();
        let mut out = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                out.push_str(
                    buffer
                        .cell((x, y))
                        .map_or("", ratatui::buffer::Cell::symbol),
                );
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn commands_bar_engines_shows_hints_and_title() {
        // Given: the engines page (k9s-style `enter/esc/jk` hints).
        // When: the bar is rendered at a typical width.
        let output = render(100, 1, Page::Engines);
        // Then: hints appear left, the page title right-aligned.
        assert_snapshot!("commands_engines", output);
        assert!(output.contains("enter open"));
        assert!(output.contains("esc quit"));
        assert!(output.contains("[Secret Engines]"));
    }

    #[test]
    fn commands_bar_secrets_shows_refresh_hint() {
        // Given: the secrets browser page.
        // When: the bar is rendered.
        let output = render(100, 1, Page::Secrets);
        // Then: the hard-refresh hint and title are present.
        assert_snapshot!("commands_secrets", output);
        assert!(output.contains("^r refresh"));
        assert!(output.contains("Secrets"));
    }

    #[test]
    fn commands_bar_secret_data_shows_all_edit_hints() {
        // Given: the secret data page.
        // When: the bar is rendered.
        let output = render(100, 1, Page::SecretData);
        // Then: reveal/edit/copy/save/tab/back hints and the title are present.
        assert_snapshot!("commands_secret_data", output);
        for hint in [
            "x reveal", "e edit", "c copy", "^s save", "tab next", "esc back",
        ] {
            assert!(output.contains(hint));
        }
        assert!(output.contains("Secret Data"));
    }

    #[test]
    fn commands_bar_config_shows_connect_hint() {
        // Given: the configuration modal page.
        // When: the bar is rendered.
        let output = render(80, 1, Page::Config);
        // Then: connect/quit hints and the title are present.
        assert_snapshot!("commands_config", output);
        assert!(output.contains("enter connect"));
        assert!(output.contains("Vault Configuration"));
    }

    #[test]
    fn test_write_and_delete_hints_appear_by_permission() {
        // Given/When: the secrets hint sets across permission combinations.
        let read_only = Page::Secrets.hints(Permission::read_only());
        let write_only = Page::Secrets.hints(Permission {
            write: true,
            ..Permission::read_only()
        });
        let full = Page::Secrets.hints(Permission::all());
        let data_readonly = Page::SecretData.hints(Permission::read_only());
        let data_writable = Page::SecretData.hints(Permission::all());

        // Then: create, delete and add-key hints are gated per capability.
        assert!(!read_only.iter().any(|(_, action)| *action == "new secret"));
        assert!(!read_only.iter().any(|(_, action)| *action == "delete"));
        assert!(write_only.iter().any(|(_, action)| *action == "new secret"));
        assert!(!write_only.iter().any(|(_, action)| *action == "delete"));
        assert!(full.iter().any(|(_, action)| *action == "delete"));
        assert!(!data_readonly.iter().any(|(_, action)| *action == "add key"));
        assert!(data_writable.iter().any(|(_, action)| *action == "add key"));
    }

    #[test]
    fn token_hints_hide_gated_actions_without_capability() {
        // Given/When: the token page across capability combinations.
        let none = Page::Token.hints(Permission::read_only());
        let full = Page::Token.hints(Permission::all());
        let create_only = Page::Token.hints(Permission {
            create_token: true,
            ..Permission::read_only()
        });
        let wrap_only = Page::Token.hints(Permission {
            wrap: true,
            ..Permission::read_only()
        });

        // Then: only permitted token actions are advertised.
        assert!(!none.iter().any(|(_, action)| *action == "new token"));
        assert!(!none.iter().any(|(_, action)| *action == "wrap"));
        assert!(full.iter().any(|(_, action)| *action == "new token"));
        assert!(full.iter().any(|(_, action)| *action == "wrap"));
        assert!(create_only.iter().any(|(_, action)| *action == "new token"));
        assert!(!create_only.iter().any(|(_, action)| *action == "wrap"));
        assert!(wrap_only.iter().any(|(_, action)| *action == "wrap"));
        assert!(!wrap_only.iter().any(|(_, action)| *action == "new token"));
    }
}
