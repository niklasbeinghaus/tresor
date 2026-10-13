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
    /// Secret version-history view.
    Versions,
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
            Self::Versions => "Versions",
        }
    }

    /// The contextual `(key, action)` hint pairs shown on the left. Create/edit
    /// and delete commands are only listed when the token holds the capability.
    #[must_use]
    pub fn hints(self, permission: Permission) -> Vec<(&'static str, &'static str)> {
        match self {
            Self::Config => vec![("enter", "connect"), ("esc", "quit")],
            Self::Engines => vec![("enter", "open"), ("esc", "quit"), ("j/k", "move")],
            Self::Secrets => {
                let mut hints = vec![("enter", "open")];
                if permission.create {
                    hints.push(("n", "new secret"));
                }
                if permission.metadata_delete {
                    hints.push(("D", "delete"));
                }
                hints.extend([("esc", "back"), ("^r", "refresh"), ("j/k", "move")]);
                hints
            }
            Self::SecretData => {
                let mut hints = vec![
                    ("x", "reveal"),
                    ("e", "edit"),
                    ("c", "copy"),
                    ("v", "versions"),
                ];
                if permission.update {
                    hints.push(("a", "add key"));
                }
                if permission.soft_delete {
                    hints.push(("d", "delete latest"));
                }
                hints.extend([("^s", "save"), ("tab", "next"), ("esc", "back")]);
                hints
            }
            Self::Versions => {
                let mut hints = vec![("enter", "preview")];
                if permission.update {
                    hints.push(("r", "restore"));
                }
                if permission.undelete {
                    hints.push(("u", "undelete"));
                }
                if permission.destroy {
                    hints.push(("X", "destroy"));
                }
                hints.extend([("esc", "back"), ("j/k", "move")]);
                hints
            }
        }
    }
}

/// What the token may do at the current path (drives which hints are shown).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "capability bits are independent and drive per-action hint visibility"
)]
pub struct Permission {
    /// Token may create secrets at the current path.
    pub create: bool,
    /// Token may update existing secret data.
    pub update: bool,
    /// Token may soft-delete specific secret versions.
    pub soft_delete: bool,
    /// Token may metadata-delete an entire secret path.
    pub metadata_delete: bool,
    /// Token may destroy secret versions permanently.
    pub destroy: bool,
    /// Token may undelete secret versions.
    pub undelete: bool,
}

impl Permission {
    /// No write or delete rights (browse-only).
    #[must_use]
    pub const fn read_only() -> Self {
        Self {
            create: false,
            update: false,
            soft_delete: false,
            metadata_delete: false,
            destroy: false,
            undelete: false,
        }
    }

    /// Full write and delete rights.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            create: true,
            update: true,
            soft_delete: true,
            metadata_delete: true,
            destroy: true,
            undelete: true,
        }
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
        // Then: reveal/edit/copy/versions/save/tab/back hints and the title are present.
        assert_snapshot!("commands_secret_data", output);
        for hint in [
            "x reveal",
            "e edit",
            "c copy",
            "v versions",
            "^s save",
            "tab next",
            "esc back",
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
            create: true,
            update: true,
            soft_delete: false,
            metadata_delete: false,
            destroy: false,
            undelete: false,
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
    fn commands_bar_versions_shows_restore_undelete_destroy_when_permitted() {
        let hints = Page::Versions.hints(Permission::all());

        assert!(hints.contains(&("r", "restore")));
        assert!(hints.contains(&("u", "undelete")));
        assert!(hints.contains(&("X", "destroy")));
    }

    #[test]
    fn commands_bar_secrets_shows_upper_d_metadata_delete() {
        let hints = Page::Secrets.hints(Permission::all());

        assert!(hints.contains(&("D", "delete")));
        assert!(!hints.contains(&("d", "delete")));
    }

    #[test]
    fn commands_bar_secret_data_shows_v_versions_and_d_delete_latest() {
        let hints = Page::SecretData.hints(Permission::all());

        assert!(hints.contains(&("v", "versions")));
        assert!(hints.contains(&("d", "delete latest")));
    }
}
