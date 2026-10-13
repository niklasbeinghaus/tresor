//! Header view renderer.

use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::theme::Theme;

/// Data rendered by the header view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderModel {
    /// Application version string.
    pub app_version: String,
    /// Vault server version string.
    pub vault_version: String,
    /// Vault server address.
    pub addr: String,
    /// Vault sealed state when known.
    pub sealed: Option<bool>,
    /// Token policy summary.
    pub policies: String,
    /// Token expiry summary.
    pub token_expiry: String,
    /// Optional transient status line.
    pub status: Option<StatusLine>,
}

/// Transient status message rendered in the header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusLine {
    /// Status severity.
    pub kind: StatusKind,
    /// Human-readable status text.
    pub text: String,
}

/// Status severity used for themed coloring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusKind {
    /// Error status.
    Error,
    /// Warning status.
    Warn,
    /// Informational status.
    Info,
    /// Success status.
    Success,
}

/// Render the top header bar.
pub fn draw_header(frame: &mut Frame<'_>, area: Rect, model: &HeaderModel, theme: &Theme) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(" tresor ", Style::default().fg(theme.title)));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
    ])
    .split(inner);
    let [wordmark_row, info_row, status_row] = rows.as_ref() else {
        return;
    };
    let info = format!(
        "addr: {} | sealed: {} | vault: {} | policies: {} | expiry: {}",
        model.addr,
        sealed_text(model.sealed),
        model.vault_version,
        model.policies,
        model.token_expiry
    );
    let wordmark = Line::from(vec![
        Span::styled("tresor", Style::default().fg(theme.title)),
        Span::raw(" "),
        Span::styled(&model.app_version, Style::default().fg(theme.revealed_fg)),
    ]);
    frame.render_widget(Paragraph::new(wordmark), *wordmark_row);
    frame.render_widget(Paragraph::new(info), *info_row);

    if let Some(status) = &model.status {
        frame.render_widget(
            Paragraph::new(status.text.as_str())
                .style(Style::default().fg(status_color(status.kind, theme))),
            *status_row,
        );
    }
}

const fn sealed_text(sealed: Option<bool>) -> &'static str {
    match sealed {
        Some(true) => "true",
        Some(false) => "false",
        None => "n/a",
    }
}

const fn status_color(kind: StatusKind, theme: &Theme) -> Color {
    match kind {
        StatusKind::Error => theme.status_error,
        StatusKind::Warn => theme.status_warn,
        StatusKind::Info => theme.status_info,
        StatusKind::Success => theme.status_success,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use insta::assert_snapshot;
    use ratatui::{Terminal, backend::TestBackend, layout::Rect};

    fn render(width: u16, height: u16, draw: impl FnOnce(&mut ratatui::Frame<'_>)) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("TestBackend");
        terminal.draw(draw).expect("draw");
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

    fn base_model(status: StatusLine) -> HeaderModel {
        HeaderModel {
            app_version: "0.1.0".into(),
            vault_version: "1.18.0".into(),
            addr: "http://127.0.0.1:8200".into(),
            sealed: Some(false),
            policies: "root".into(),
            token_expiry: "eternal".into(),
            status: Some(status),
        }
    }

    #[test]
    fn header_shows_status_success() {
        let model = base_model(StatusLine {
            kind: StatusKind::Success,
            text: "connected".into(),
        });
        assert_snapshot!(
            "header_success",
            render(100, 12, |f| draw_header(
                f,
                Rect::new(0, 0, 100, 12),
                &model,
                &Theme::default()
            ))
        );
    }

    #[test]
    fn header_shows_status_error() {
        let model = base_model(StatusLine {
            kind: StatusKind::Error,
            text: "permission denied".into(),
        });
        assert_snapshot!(
            "header_error",
            render(80, 8, |f| draw_header(
                f,
                Rect::new(0, 0, 80, 8),
                &model,
                &Theme::default()
            ))
        );
    }

    #[test]
    fn header_shows_unknown_seal_state() {
        let model = HeaderModel {
            app_version: "0.1.0".into(),
            vault_version: "n/a".into(),
            addr: "http://vault.local".into(),
            sealed: None,
            policies: "n/a".into(),
            token_expiry: "n/a".into(),
            status: Some(StatusLine {
                kind: StatusKind::Warn,
                text: "not configured".into(),
            }),
        };
        assert_snapshot!(
            "header_unknown_seal_state",
            render(80, 8, |f| draw_header(
                f,
                Rect::new(0, 0, 80, 8),
                &model,
                &Theme::default()
            ))
        );
    }
}
