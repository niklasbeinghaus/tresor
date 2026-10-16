//! Command palette popup renderer (`:`).

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use crate::theme::Theme;

/// One command-palette entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaletteRow {
    /// Command name, e.g. `ctx` (rendered as `:ctx`).
    pub label: String,
    /// Short human description.
    pub description: String,
}

/// Render model for the command palette popup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaletteModel {
    /// Query typed after `:`.
    pub query: String,
    /// Matching command rows, best match first.
    pub rows: Vec<PaletteRow>,
    /// Selected row index into `rows`.
    pub selected: usize,
    /// Optional command dispatch error (e.g. unknown command).
    pub error: Option<String>,
}

/// Most rows the palette popup shows at once.
const MAX_ROWS: usize = 10;

/// Draws the centered command-palette popup over `area`.
pub fn draw_palette(frame: &mut Frame<'_>, area: Rect, model: &PaletteModel, theme: &Theme) {
    let width = (area.width.saturating_mul(2) / 3)
        .clamp(32, 72)
        .min(area.width);
    let visible = model.rows.len().clamp(1, MAX_ROWS);
    let height = u16::try_from(visible)
        .unwrap_or(u16::MAX)
        .saturating_add(4)
        .min(area.height);
    let popup = centered(area, width, height);
    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(
            "Commands",
            Style::default()
                .fg(theme.title)
                .add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
    ])
    .split(inner);
    let [input_row, hint_row, list_row] = rows.as_ref() else {
        return;
    };

    frame.render_widget(Paragraph::new(palette_input(model, theme)), *input_row);
    let hint = model.error.as_ref().map_or_else(
        || {
            Line::from(Span::styled(
                "enter run │ esc cancel",
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
    frame.render_widget(Paragraph::new(hint), *hint_row);

    let list_width = usize::from(list_row.width);
    let lines: Vec<Line<'_>> = if model.rows.is_empty() {
        vec![Line::from(Span::styled(
            "(no matching commands)",
            Style::default().fg(theme.masked_fg),
        ))]
    } else {
        model
            .rows
            .iter()
            .take(MAX_ROWS)
            .enumerate()
            .map(|(index, row)| palette_line(index, model.selected, row, theme, list_width))
            .collect()
    };
    frame.render_widget(Paragraph::new(lines), *list_row);
}

fn palette_input<'a>(model: &'a PaletteModel, theme: &Theme) -> Line<'a> {
    Line::from(vec![
        Span::styled(
            ":",
            Style::default()
                .fg(theme.title)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(model.query.as_str(), Style::default().fg(theme.selected_fg)),
        Span::styled("█", Style::default().fg(theme.title)),
    ])
}

fn palette_line(
    index: usize,
    selected: usize,
    row: &PaletteRow,
    theme: &Theme,
    width: usize,
) -> Line<'static> {
    let is_selected = index == selected;
    let label_fg = if is_selected {
        theme.selected_fg
    } else {
        theme.title
    };
    let desc_fg = if is_selected {
        theme.selected_fg
    } else {
        theme.masked_fg
    };
    let label = format!(":{}", row.label);
    let used = label.chars().count() + 2 + row.description.chars().count();
    let pad = width.saturating_sub(used);
    let spans = vec![
        Span::styled(
            label,
            Style::default().fg(label_fg).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  {}", row.description),
            Style::default().fg(desc_fg),
        ),
        Span::raw(" ".repeat(pad)),
    ];
    let style = if is_selected {
        Style::default().bg(theme.selected_bg)
    } else {
        Style::default()
    };
    Line::from(spans).style(style)
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

    fn render(model: &PaletteModel) -> String {
        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).expect("TestBackend");
        terminal
            .draw(|frame| {
                draw_palette(frame, frame.area(), model, &Theme::default());
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

    fn rows() -> Vec<PaletteRow> {
        vec![
            PaletteRow {
                label: "ctx".to_owned(),
                description: "switch connection context".to_owned(),
            },
            PaletteRow {
                label: "filter".to_owned(),
                description: "filter the focused list".to_owned(),
            },
            PaletteRow {
                label: "quit".to_owned(),
                description: "exit tresor".to_owned(),
            },
        ]
    }

    #[test]
    fn palette_shows_commands_when_query_is_empty() {
        // Given: an empty query and the full command list.
        let model = PaletteModel {
            query: String::new(),
            rows: rows(),
            selected: 0,
            error: None,
        };

        // When: the palette is rendered.
        let output = render(&model);

        // Then: the title, query cursor and every command are visible.
        assert_snapshot!("palette_all_commands", output);
        assert!(output.contains("Commands"));
        assert!(output.contains(":ctx"));
        assert!(output.contains("switch connection context"));
    }

    #[test]
    fn palette_shows_query_and_selection_when_filtering() {
        // Given: a partial query with the matching row selected.
        let model = PaletteModel {
            query: "fi".to_owned(),
            rows: vec![PaletteRow {
                label: "filter".to_owned(),
                description: "filter the focused list".to_owned(),
            }],
            selected: 0,
            error: None,
        };

        // When: the palette is rendered.
        let output = render(&model);

        // Then: the query text and the matching command are shown.
        assert_snapshot!("palette_filtered", output);
        assert!(output.contains(":fi"));
        assert!(output.contains(":filter"));
    }

    #[test]
    fn palette_shows_placeholder_when_nothing_matches() {
        // Given: a query that matches no command.
        let model = PaletteModel {
            query: "zzz".to_owned(),
            rows: Vec::new(),
            selected: 0,
            error: None,
        };

        // When: the palette is rendered.
        let output = render(&model);

        // Then: the empty-state line is shown.
        assert_snapshot!("palette_empty", output);
        assert!(output.contains("(no matching commands)"));
    }

    #[test]
    fn palette_shows_error_when_present() {
        // Given: a query that failed to resolve to a command.
        let model = PaletteModel {
            query: "zzz".to_owned(),
            rows: Vec::new(),
            selected: 0,
            error: Some("unknown command: zzz".to_owned()),
        };

        // When: the palette is rendered.
        let output = render(&model);

        // Then: the error replaces the confirm hint line.
        assert_snapshot!("palette_error", output);
        assert!(output.contains("unknown command: zzz"));
        assert!(!output.contains("enter run"));
    }
}
