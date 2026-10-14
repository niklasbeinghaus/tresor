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
    /// ACL policies browser.
    Policies,
    /// Secret key/value view.
    SecretData,
    /// Secret version-history view.
    Versions,
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
            Self::Policies => "[Policies]",
            Self::SecretData => "Secret Data",
            Self::Versions => "Versions",
            Self::Token => "Token Inspector",
        }
    }

    /// The contextual `(key, action)` hint pairs shown on the left.
    #[must_use]
    pub fn hints(self, permission: Permission) -> Vec<(&'static str, &'static str)> {
        match self {
            Self::Config => vec![("enter", "connect"), ("esc", "quit")],
            Self::Engines => vec![("enter", "open"), ("esc", "quit"), ("j/k", "move")],
            Self::Token => token_hints(permission),
            Self::Secrets => {
                let mut hints = vec![("enter", "open")];
                if permission.create || permission.write {
                    hints.push(("n", "new secret"));
                }
                if permission.metadata_delete || permission.delete {
                    hints.push(("D", "delete"));
                }
                hints.extend([("esc", "back"), ("^r", "refresh"), ("j/k", "move")]);
                hints
            }
            Self::Policies => {
                let mut hints = vec![("enter", "preview")];
                if permission.create || permission.write {
                    hints.push(("e", "edit"));
                    hints.push(("n", "new"));
                }
                hints.extend([("esc", "engines"), (":", "command"), ("j/k", "move")]);
                hints
            }
            Self::SecretData => {
                let mut hints = vec![("x", "reveal"), ("e", "edit"), ("c", "copy"), ("v", "versions")];
                if permission.update || permission.write {
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
                if permission.update || permission.write {
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
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent capability flags grouped for command-bar rendering"
)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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
    /// Token may create/update secrets here (legacy alias used by some views).
    pub write: bool,
    /// Token may delete secrets here (legacy alias used by some views).
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
            create: false,
            update: false,
            soft_delete: false,
            metadata_delete: false,
            destroy: false,
            undelete: false,
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
            create: true,
            update: true,
            soft_delete: true,
            metadata_delete: true,
            destroy: true,
            undelete: true,
            write: true,
            delete: true,
            create_token: true,
            wrap: true,
        }
    }
}

/// Optional transient input or status rendered in place of the key hints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandBarInput<'a> {
    /// The `:` command palette is capturing input.
    Command {
        /// Text typed after `:`.
        input: &'a str,
    },
    /// A list filter is active; show the query and match count.
    Filter {
        /// Filter query typed after `/`.
        query: &'a str,
        /// Number of rows matching the query.
        matched: usize,
        /// Total number of rows in the focused list.
        total: usize,
    },
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
    draw_commands_with_input(frame, area, page, permission, None, theme);
}

/// Draws the command bar, replacing the key hints with the active `:` command
/// input or `/` filter status when one is given.
pub fn draw_commands_with_input(
    frame: &mut Frame<'_>,
    area: Rect,
    page: Page,
    permission: Permission,
    input: Option<CommandBarInput<'_>>,
    theme: &Theme,
) {
    let line = match input {
        Some(CommandBarInput::Command { input }) => command_line(input, theme),
        Some(CommandBarInput::Filter {
            query,
            matched,
            total,
        }) => filter_line(query, matched, total, theme),
        None => hints_line(page, permission, area, theme),
    };
    frame.render_widget(
        Paragraph::new(line).style(Style::default().bg(theme.selected_bg)),
        area,
    );
}

fn hints_line(page: Page, permission: Permission, area: Rect, theme: &Theme) -> Line<'static> {
    let mut spans = Vec::new();
    let mut left_width = 0usize;
    for (index, (key, action)) in page.hints(permission).iter().enumerate() {
        if index > 0 {
            spans.push(Span::raw(" │ "));
            left_width += 3;
        }
        spans.push(Span::styled(
            *key,
            Style::default()
                .fg(theme.title)
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::raw(format!(" {action}")));
        left_width += key.len() + 1 + action.len();
    }
    let title = page.title();
    let pad = usize::from(area.width).saturating_sub(left_width + title.len());
    spans.push(Span::raw(" ".repeat(pad)));
    spans.push(Span::styled(
        title,
        Style::default()
            .fg(theme.title)
            .add_modifier(Modifier::BOLD),
    ));
    Line::from(spans)
}

fn command_line(input: &str, theme: &Theme) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            ":",
            Style::default()
                .fg(theme.title)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(input.to_owned(), Style::default().fg(theme.selected_fg)),
        Span::styled("█", Style::default().fg(theme.title)),
    ])
}

fn filter_line(query: &str, matched: usize, total: usize, theme: &Theme) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            "/",
            Style::default()
                .fg(theme.title)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(query.to_owned(), Style::default().fg(theme.selected_fg)),
        Span::styled("█", Style::default().fg(theme.title)),
        Span::styled(
            format!("  {matched}/{total} matches"),
            Style::default().fg(theme.masked_fg),
        ),
    ])
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
    fn commands_bar_policies_shows_contextual_hints() {
        let backend = TestBackend::new(100, 1);
        let mut terminal = Terminal::new(backend).expect("TestBackend");
        terminal
            .draw(|frame| {
                draw_commands(
                    frame,
                    Rect::new(0, 0, 100, 1),
                    Page::Policies,
                    Permission::all(),
                    &Theme::default(),
                );
            })
            .expect("draw");
        let buffer = terminal.backend().buffer();
        let mut output = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                output.push_str(
                    buffer
                        .cell((x, y))
                        .map_or("", ratatui::buffer::Cell::symbol),
                );
            }
            output.push('\n');
        }
        assert!(output.contains("enter preview"));
        assert!(output.contains("e edit"));
        assert!(output.contains("n new"));
        assert!(output.contains("[Policies]"));
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
<<<<<<< HEAD
            create: true,
            update: true,
            soft_delete: false,
            metadata_delete: false,
            destroy: false,
            undelete: false,
=======
            write: true,
            ..Permission::read_only()
>>>>>>> origin/main
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

<<<<<<< HEAD
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
=======
    fn render_input(width: u16, height: u16, page: Page, input: CommandBarInput<'_>) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("TestBackend");
        terminal
            .draw(|frame| {
                draw_commands_with_input(
                    frame,
                    Rect::new(0, 0, width, height),
                    page,
                    Permission::read_only(),
                    Some(input),
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
    fn commands_bar_shows_command_prompt_when_command_input_active() {
        // Given: the `:` command palette is capturing input.
        let output = render_input(
            100,
            1,
            Page::Engines,
            CommandBarInput::Command { input: "ctx" },
        );

        // Then: the bar shows the prompt instead of the key hints.
        assert_snapshot!("commands_command_input", output);
        assert!(output.contains(":ctx"));
    }

    #[test]
    fn commands_bar_shows_match_count_when_filter_active() {
        // Given: an active `/` filter over the secrets list.
        let output = render_input(
            100,
            1,
            Page::Secrets,
            CommandBarInput::Filter {
                query: "ap",
                matched: 3,
                total: 12,
            },
        );

        // Then: the query and match count are shown.
        assert_snapshot!("commands_filter_status", output);
        assert!(output.contains("/ap"));
        assert!(output.contains("3/12 matches"));
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
>>>>>>> origin/main
    }
}
