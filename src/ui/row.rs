//! Shared list-row rendering.
//!
//! Hand-rolled `Paragraph` rows must (a) carry a visible marker and (b) pad the
//! selection style across the full row width — otherwise a selected row of
//! ordinary entries (whose foreground matches the selection foreground) shows
//! almost no visible change, unlike directory rows which differ by color.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use crate::theme::Theme;

/// The selection marker shown at the start of the highlighted row (sofka-style).
pub const SELECTION_MARKER: &str = "\u{258c}";

/// Builds one list row: `▌` marker when selected, `label` in `base_fg`, padded
/// to `width` so the selection background spans the entire row.
pub fn row_line(
    index: usize,
    selected: Option<usize>,
    label: &str,
    base_fg: Color,
    theme: &Theme,
    width: u16,
) -> Line<'static> {
    let is_selected = selected == Some(index);
    let marker = if is_selected {
        format!("{SELECTION_MARKER} ")
    } else {
        "  ".to_owned()
    };
    let text = format!("{marker}{label}");
    let padded = format!("{text:<width$}", width = usize::from(width));
    let style = if is_selected {
        Style::default()
            .bg(theme.selected_bg)
            .fg(theme.selected_fg)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(base_fg)
    };
    Line::from(Span::styled(padded, style))
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::layout::Rect;
    use ratatui::widgets::Paragraph;

    use super::*;

    fn render_row(selected: Option<usize>, width: u16) -> ratatui::buffer::Buffer {
        let backend = TestBackend::new(width, 1);
        let mut terminal = Terminal::new(backend).expect("TestBackend");
        terminal
            .draw(|frame| {
                let line = row_line(
                    0,
                    selected,
                    "leaf-entry",
                    Color::White,
                    &Theme::default(),
                    width,
                );
                frame.render_widget(Paragraph::new(line), Rect::new(0, 0, width, 1));
            })
            .expect("draw");
        terminal.backend().buffer().clone()
    }

    #[test]
    fn test_row_line_selected_spans_full_width_and_marker() {
        // Given/When: a selected leaf row is rendered.
        let buffer = render_row(Some(0), 20);
        // Then: the marker leads the row and the selection background reaches the
        // last cell (proving the whole row is highlighted, not just the label).
        let first = buffer.cell((0, 0)).expect("cell");
        assert_eq!(first.symbol(), SELECTION_MARKER);
        let last = buffer.cell((19, 0)).expect("last cell");
        assert_eq!(last.style().bg, Some(Theme::default().selected_bg));
    }

    #[test]
    fn test_row_line_unselected_has_no_marker_or_background() {
        // Given/When: an unselected row is rendered.
        let buffer = render_row(None, 20);
        // Then: no marker glyph and no selection background.
        let first = buffer.cell((0, 0)).expect("cell");
        assert_ne!(first.symbol(), SELECTION_MARKER);
        assert_ne!(first.style().bg, Some(Theme::default().selected_bg));
    }
}
