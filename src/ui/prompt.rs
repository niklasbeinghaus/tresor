//! Single-field input prompt (new secret name / new key name), rendered as a
//! centered popup over the body area.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use crate::theme::Theme;

/// What the prompt is collecting (drives its title and hint text).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptKind {
    /// A name for a new secret inside the current directory.
    NewSecret,
    /// A name for a new key inside the current secret.
    NewKey,
    /// Confirmation before deleting a secret (`input` holds its name).
    DeleteSecret,
    /// A `:` command-palette entry.
    Command,
    /// Policies for a child token (comma/space separated).
    ChildTokenPolicies,
    /// TTL for a child token (e.g. `1h`; blank for the server default).
    ChildTokenTtl,
    /// Use limit for a child token (blank for unlimited).
    ChildTokenUses,
    /// JSON payload to response-wrap.
    WrapPayload,
    /// Wrap TTL (blank for the server default).
    WrapTtl,
    /// A wrapping token to unwrap (rendered masked).
    UnwrapToken,
}

impl PromptKind {
    /// The popup title for this prompt.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::NewSecret => "New Secret",
            Self::NewKey => "New Key",
            Self::DeleteSecret => "Delete Secret",
            Self::Command => "Command",
            Self::ChildTokenPolicies => "Child Token: Policies",
            Self::ChildTokenTtl => "Child Token: TTL",
            Self::ChildTokenUses => "Child Token: Use Limit",
            Self::WrapPayload => "Wrap Payload",
            Self::WrapTtl => "Wrap TTL",
            Self::UnwrapToken => "Unwrap Token",
        }
    }

    /// The field label for this prompt.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NewSecret => "Secret name",
            Self::NewKey => "Key name",
            Self::DeleteSecret => "Confirm",
            Self::Command => "Command",
            Self::ChildTokenPolicies => "Policies (comma separated)",
            Self::ChildTokenTtl => "TTL (e.g. 1h)",
            Self::ChildTokenUses => "Use limit",
            Self::WrapPayload => "Payload (JSON)",
            Self::WrapTtl => "TTL (e.g. 5m)",
            Self::UnwrapToken => "Wrapping token",
        }
    }

    /// True when the prompt refuses an empty submission.
    ///
    /// The TTL/use-limit/policy fields may be left blank (server defaults).
    #[must_use]
    pub const fn requires_input(self) -> bool {
        !matches!(
            self,
            Self::ChildTokenPolicies | Self::ChildTokenTtl | Self::ChildTokenUses | Self::WrapTtl
        )
    }

    /// True when the typed input is sensitive and must render masked.
    #[must_use]
    pub const fn masked_input(self) -> bool {
        matches!(self, Self::UnwrapToken)
    }
}

/// Data rendered by the input prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptModel {
    /// What is being collected.
    pub kind: PromptKind,
    /// Current input text.
    pub input: String,
    /// Optional error shown under the field (e.g. permission denied).
    pub error: Option<String>,
}

/// Draws the centered input prompt over `area`.
pub fn draw_prompt(frame: &mut Frame<'_>, area: Rect, model: &PromptModel, theme: &Theme) {
    // Size the popup to roughly half the area, clamped to something usable.
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

    let field = if model.kind == PromptKind::DeleteSecret {
        Line::from(Span::styled(
            format!("delete secret '{}'?", model.input),
            Style::default().fg(theme.status_warn),
        ))
    } else {
        let shown = if model.kind.masked_input() {
            "*".repeat(model.input.chars().count())
        } else {
            model.input.clone()
        };
        Line::from(vec![
            Span::styled(
                format!("{}: ", model.kind.label()),
                Style::default().fg(theme.leaf_fg),
            ),
            Span::styled(
                shown,
                Style::default().fg(theme.selected_fg).bg(theme.selected_bg),
            ),
        ])
    };
    frame.render_widget(Paragraph::new(field), *field_row);

    let message = model.error.as_ref().map_or_else(
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
}
