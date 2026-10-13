//! Single-field input prompt (new secret/key/policy), rendered as a centered popup.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use crate::theme::Theme;

/// What the prompt is collecting (drives title and labels).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptKind {
    /// A name for a new secret inside the current directory.
    NewSecret,
    /// A name for a new key inside the current secret.
    NewKey,
    /// Confirmation before deleting a secret (`input` holds the name).
    DeleteSecret,
    /// A name for a new ACL policy.
    NewPolicy,
    /// Confirmation before saving ACL policy changes.
    SavePolicy,
}

impl PromptKind {
    /// Popup title for this prompt.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::NewSecret => "New Secret",
            Self::NewKey => "New Key",
            Self::DeleteSecret => "Delete Secret",
            Self::NewPolicy => "New Policy",
            Self::SavePolicy => "Save Policy",
        }
    }

    /// Field label for this prompt.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NewSecret => "Secret name",
            Self::NewKey => "Key name",
            Self::DeleteSecret | Self::SavePolicy => "Confirm",
            Self::NewPolicy => "Policy name",
        }
    }
}

/// Data rendered by the prompt popup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptModel {
    /// Prompt kind.
    pub kind: PromptKind,
    /// Current input text.
    pub input: String,
    /// Optional error shown in the message row.
    pub error: Option<String>,
    /// Optional detail shown in the message row.
    pub detail: Option<String>,
}

/// Draws the centered prompt over `area`.
pub fn draw_prompt(frame: &mut Frame<'_>, area: Rect, model: &PromptModel, theme: &Theme) {
    let width = (area.width / 2).clamp(24, 80).min(area.width);
    let height = 7.min(area.height);
    let popup = centered(area, width, height);
    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(
            model.kind.title(),
            Style::default()
                .fg(theme.title)
                .add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let rows = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).split(inner);
    let [field_row, message_row] = rows.as_ref() else {
        return;
    };

    let field = match model.kind {
        PromptKind::DeleteSecret => Line::from(Span::styled(
            format!("delete secret '{}'?", model.input),
            Style::default().fg(theme.status_warn),
        )),
        PromptKind::SavePolicy => Line::from(Span::styled(
            format!("save policy '{}' ?", model.input),
            Style::default().fg(theme.status_warn),
        )),
        PromptKind::NewSecret | PromptKind::NewKey | PromptKind::NewPolicy => Line::from(vec![
            Span::styled(
                format!("{}: ", model.kind.label()),
                Style::default().fg(theme.leaf_fg),
            ),
            Span::styled(
                model.input.as_str(),
                Style::default().fg(theme.selected_fg).bg(theme.selected_bg),
            ),
        ]),
    };
    frame.render_widget(Paragraph::new(field), *field_row);

    let base_message = model.error.as_ref().map_or_else(
        || {
            Line::from(Span::styled(
                "enter confirm │ esc cancel",
                Style::default().fg(theme.masked_fg),
            ))
        },
        |error| {
            Line::from(Span::styled(
                error.as_str(),
                Style::default().fg(theme.status_error),
            ))
        },
    );
    let message = model.detail.as_ref().map_or(base_message, |detail| {
        Line::from(vec![
            Span::styled(detail.as_str(), Style::default().fg(theme.masked_fg)),
            Span::raw("  │  "),
            Span::styled(
                "enter confirm │ esc cancel",
                Style::default().fg(theme.masked_fg),
            ),
        ])
    });
    frame.render_widget(Paragraph::new(message), *message_row);
}

const fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    Rect::new(x, y, width, height)
}

#[cfg(test)]
mod tests {
    use insta::assert_snapshot;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;

    fn render(kind: PromptKind, input: &str, error: Option<&str>) -> String {
        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).expect("TestBackend");
        let model = PromptModel {
            kind,
            input: input.to_owned(),
            error: error.map(str::to_owned),
            detail: None,
        };
        terminal
            .draw(|frame| {
                draw_prompt(frame, frame.area(), &model, &Theme::default());
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
    fn prompt_new_secret_shows_title_label_and_hint() {
        // Given: a new-secret prompt with a typed name.
        // When: it is rendered.
        let output = render(PromptKind::NewSecret, "team/creds", None);
        // Then: the title, label, input and confirm hint are visible.
        assert_snapshot!("prompt_new_secret", output);
        assert!(output.contains("New Secret"));
        assert!(output.contains("Secret name"));
        assert!(output.contains("team/creds"));
        assert!(output.contains("enter confirm"));
    }

    #[test]
    fn prompt_shows_error_when_present() {
        // Given: a prompt carrying a permission error.
        // When: it is rendered.
        let output = render(PromptKind::NewKey, "token", Some("permission denied"));
        // Then: the error line replaces the hint.
        assert_snapshot!("prompt_error", output);
        assert!(output.contains("permission denied"));
    }

    #[test]
    fn prompt_delete_shows_confirmation_question() {
        // Given: a delete confirmation for a named secret.
        // When: it is rendered.
        let output = render(PromptKind::DeleteSecret, "team/creds", None);
        // Then: the question names the secret and the confirm hint is shown.
        assert_snapshot!("prompt_delete_confirm", output);
        assert!(output.contains("delete secret 'team/creds'?"));
        assert!(output.contains("enter confirm"));
    }

    #[test]
    fn prompt_new_policy_shows_title() {
        let output = render(PromptKind::NewPolicy, "team", None);
        assert_snapshot!("prompt_new_policy", output);
        assert!(output.contains("New Policy"));
    }

    #[test]
    fn prompt_save_policy_shows_confirmation_and_detail() {
        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).expect("TestBackend");
        let model = PromptModel {
            kind: PromptKind::SavePolicy,
            input: "team".to_owned(),
            error: None,
            detail: Some("10 bytes / 1 lines → 20 bytes / 2 lines".to_owned()),
        };
        terminal
            .draw(|frame| {
                draw_prompt(frame, frame.area(), &model, &Theme::default());
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
        assert_snapshot!("prompt_save_policy", out);
    }
}
