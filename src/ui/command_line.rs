//! Minimal `:` command-line renderer.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::theme::Theme;

/// Data rendered by the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandLineModel {
    /// Command text without leading `:`.
    pub input: String,
    /// Optional command-line error.
    pub error: Option<String>,
}

/// Draws the one-row `:` command line in the command-bar area.
pub fn draw_command_line(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &CommandLineModel,
    theme: &Theme,
) {
    let mut spans = vec![
        Span::styled(
            ":",
            Style::default()
                .fg(theme.title)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            model.input.as_str(),
            Style::default().fg(theme.selected_fg).bg(theme.selected_bg),
        ),
    ];
    if let Some(error) = &model.error {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            error.as_str(),
            Style::default().fg(theme.status_error),
        ));
    }
    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(theme.selected_bg)),
        area,
    );
}

#[cfg(test)]
mod tests {
    use insta::assert_snapshot;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::{CommandLineModel, draw_command_line};
    use crate::theme::Theme;

    fn render(model: &CommandLineModel) -> String {
        let backend = TestBackend::new(100, 1);
        let mut terminal = Terminal::new(backend).expect("TestBackend");
        terminal
            .draw(|frame| {
                draw_command_line(frame, frame.area(), model, &Theme::default());
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
    fn command_line_shows_input() {
        let output = render(&CommandLineModel {
            input: "policies".to_owned(),
            error: None,
        });
        assert_snapshot!("command_line_policies", output);
    }

    #[test]
    fn command_line_shows_error() {
        let output = render(&CommandLineModel {
            input: "wat".to_owned(),
            error: Some("unknown command: wat".to_owned()),
        });
        assert_snapshot!("command_line_error", output);
    }
}
