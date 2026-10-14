//! Token inspector renderer: token details plus an optional preview pane for a
//! minted child token, a wrapping token, or an unwrapped payload.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::theme::Theme;

/// Optional preview pane shown beside the token details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaneModel {
    /// Pane border title.
    pub title: String,
    /// Optional warning rendered above the body (e.g. "shown once").
    pub warning: Option<String>,
    /// Pane body text.
    pub body: String,
}

/// Render model for the token inspector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenViewModel {
    /// True once token details have loaded.
    pub loaded: bool,
    /// Token accessor.
    pub accessor: String,
    /// Token display name.
    pub display_name: String,
    /// Comma-separated token policies.
    pub policies: String,
    /// Remaining TTL summary.
    pub ttl: String,
    /// Expiry summary (`never` for non-expiring tokens).
    pub expire_time: String,
    /// Whether the token is renewable.
    pub renewable: bool,
    /// Remaining-uses summary.
    pub num_uses: String,
    /// Whether the token is an orphan.
    pub orphan: bool,
    /// Optional preview pane.
    pub pane: Option<PaneModel>,
}

/// Draws the token inspector: details on the left, preview pane on the right
/// when a pane is present.
pub fn draw_token(frame: &mut Frame<'_>, area: Rect, model: &TokenViewModel, theme: &Theme) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(
            "Token Inspector",
            Style::default().fg(theme.title),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if !model.loaded {
        frame.render_widget(
            Paragraph::new("loading token...").style(Style::default().fg(theme.masked_fg)),
            inner,
        );
        return;
    }

    match &model.pane {
        Some(pane) => {
            let panes = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
                .split(inner);
            let [left, right] = panes.as_ref() else {
                return;
            };
            draw_details(frame, *left, model, theme);
            draw_pane(frame, *right, pane, theme);
        }
        None => draw_details(frame, inner, model, theme),
    }
}

fn draw_details(frame: &mut Frame<'_>, area: Rect, model: &TokenViewModel, theme: &Theme) {
    let rows = [
        ("accessor", model.accessor.clone()),
        ("display name", model.display_name.clone()),
        ("policies", model.policies.clone()),
        ("ttl", model.ttl.clone()),
        ("expires", model.expire_time.clone()),
        ("renewable", yes_no(model.renewable)),
        ("use limit", model.num_uses.clone()),
        ("orphan", yes_no(model.orphan)),
    ];
    let lines: Vec<Line<'_>> = rows
        .into_iter()
        .map(|(label, value)| {
            Line::from(vec![
                Span::styled(
                    format!("{label}: "),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(value, Style::default().fg(theme.revealed_fg)),
            ])
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), area);
}

fn draw_pane(frame: &mut Frame<'_>, area: Rect, pane: &PaneModel, theme: &Theme) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.editor_border))
        .title(Span::styled(
            pane.title.as_str(),
            Style::default().fg(theme.title),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines: Vec<Line<'_>> = Vec::new();
    if let Some(warning) = &pane.warning {
        lines.push(Line::from(Span::styled(
            warning.as_str(),
            Style::default().fg(theme.status_warn),
        )));
    }
    for line in pane.body.lines() {
        lines.push(Line::from(Span::styled(
            line.to_owned(),
            Style::default().fg(theme.revealed_fg),
        )));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn yes_no(value: bool) -> String {
    if value { "yes" } else { "no" }.to_owned()
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    reason = "snapshot test helper follows the contract supplied by the task"
)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;

    fn render(width: u16, height: u16, model: &TokenViewModel) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("TestBackend");
        terminal
            .draw(|frame| draw_token(frame, frame.area(), model, &Theme::default()))
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

    fn loaded(pane: Option<PaneModel>) -> TokenViewModel {
        TokenViewModel {
            loaded: true,
            accessor: "9f8e7d6c".to_owned(),
            display_name: "oidc-platform".to_owned(),
            policies: "default, platform-eng".to_owned(),
            ttl: "58m 12s".to_owned(),
            expire_time: "2026-10-13T11:00:00Z".to_owned(),
            renewable: true,
            num_uses: "unlimited".to_owned(),
            orphan: false,
            pane,
        }
    }

    #[test]
    fn draw_token_shows_details_when_loaded() {
        // Given: a loaded token with no preview pane.
        let model = loaded(None);

        // When: the inspector is rendered.
        let actual = render(100, 16, &model);

        // Then: the title and every detail row are stable.
        insta::assert_snapshot!(actual);
        assert!(actual.contains("Token Inspector"));
        assert!(actual.contains("oidc-platform"));
        assert!(actual.contains("2026-10-13T11:00:00Z"));
    }

    #[test]
    fn draw_token_shows_loading_placeholder_when_not_loaded() {
        // Given: a token inspector before details have loaded.
        let model = TokenViewModel {
            loaded: false,
            ..loaded(None)
        };

        // When: the inspector is rendered.
        let actual = render(80, 10, &model);

        // Then: a loading placeholder is shown instead of rows.
        insta::assert_snapshot!(actual);
        assert!(actual.contains("loading token"));
    }

    #[test]
    fn draw_token_shows_minted_token_pane_when_present() {
        // Given: a loaded token with a freshly minted child token pane.
        let model = loaded(Some(PaneModel {
            title: "New Token (shown once)".to_owned(),
            warning: Some("copy now - this token is never shown again".to_owned()),
            body: "hvs.CAESIJminted-child-token".to_owned(),
        }));

        // When: the inspector is rendered.
        let actual = render(110, 14, &model);

        // Then: the pane title, warning and token body are visible.
        insta::assert_snapshot!(actual);
        assert!(actual.contains("New Token (shown once)"));
        assert!(actual.contains("never shown again"));
        assert!(actual.contains("hvs.CAESIJminted-child-token"));
    }

    #[test]
    fn draw_token_shows_unwrapped_payload_pane_without_warning() {
        // Given: a loaded token with an unwrapped payload pane.
        let model = loaded(Some(PaneModel {
            title: "Unwrapped Payload".to_owned(),
            warning: None,
            body: "{\n  \"password\": \"hunter2\"\n}".to_owned(),
        }));

        // When: the inspector is rendered.
        let actual = render(100, 12, &model);

        // Then: the payload body is rendered verbatim.
        insta::assert_snapshot!(actual);
        assert!(actual.contains("Unwrapped Payload"));
        assert!(actual.contains("hunter2"));
    }
}
