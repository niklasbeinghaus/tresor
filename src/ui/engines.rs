//! Secret engine list renderer.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use super::row::row_line;
use crate::constants::titles;
use crate::model::SecretEntry;
use crate::theme::Theme;

/// Data rendered by the secret engine list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnginesModel {
    /// Available secret engines.
    pub engines: Vec<SecretEntry>,
    /// Selected engine index.
    pub selected: usize,
}

/// Render the secret engine list.
pub fn draw_engines(frame: &mut Frame<'_>, area: Rect, model: &EnginesModel, theme: &Theme) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(
            titles::ENGINES,
            Style::default().fg(theme.title),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let selected = selected_index(model.selected, model.engines.len());
    let visible_rows = usize::from(inner.height);
    let lines: Vec<Line<'_>> = model
        .engines
        .iter()
        .take(visible_rows)
        .enumerate()
        .map(|(index, entry)| engine_line(index, selected, entry, theme, inner.width))
        .collect();
    frame.render_widget(Paragraph::new(lines), inner);
}

fn engine_line(
    index: usize,
    selected: Option<usize>,
    entry: &SecretEntry,
    theme: &Theme,
    width: u16,
) -> Line<'static> {
    row_line(
        index,
        selected,
        entry.name.as_str(),
        theme.leaf_fg,
        theme,
        width,
    )
}

fn selected_index(selected: usize, len: usize) -> Option<usize> {
    len.checked_sub(1).map(|last| selected.min(last))
}

#[cfg(test)]
mod tests {
    use insta::assert_snapshot;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::layout::Rect;

    use super::*;

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

    fn engines() -> Vec<SecretEntry> {
        vec![
            SecretEntry::leaf("secret"),
            SecretEntry::leaf("kv"),
            SecretEntry::leaf("team"),
            SecretEntry::leaf("infra"),
            SecretEntry::leaf("apps"),
        ]
    }

    #[test]
    fn engines_selects_first_row() {
        let model = EnginesModel {
            engines: engines(),
            selected: 0,
        };
        assert_snapshot!(
            "engines_selected_first",
            render(32, 8, |f| draw_engines(
                f,
                Rect::new(0, 0, 32, 8),
                &model,
                &Theme::default()
            ))
        );
    }

    #[test]
    fn engines_clamps_selection_to_last_row() {
        let model = EnginesModel {
            engines: engines(),
            selected: 30,
        };
        assert_snapshot!(
            "engines_selection_clamped",
            render(32, 8, |f| draw_engines(
                f,
                Rect::new(0, 0, 32, 8),
                &model,
                &Theme::default()
            ))
        );
    }

    #[test]
    fn engines_empty_list() {
        let model = EnginesModel {
            engines: Vec::new(),
            selected: 0,
        };
        assert_snapshot!(
            "engines_empty",
            render(32, 5, |f| draw_engines(
                f,
                Rect::new(0, 0, 32, 5),
                &model,
                &Theme::default()
            ))
        );
    }
}
