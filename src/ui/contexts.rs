//! Connection context picker popup renderer (`:ctx`).

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use crate::theme::Theme;

/// One connection context row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextRow {
    /// Profile name.
    pub name: String,
    /// Vault server address.
    pub addr: String,
    /// Whether this is the currently connected profile.
    pub current: bool,
}

/// Render model for the connection picker popup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextsModel {
    /// Profile rows (already filtered/sorted), display order.
    pub rows: Vec<ContextRow>,
    /// Selected row index into `rows`.
    pub selected: usize,
    /// Type-to-filter buffer.
    pub filter: String,
    /// Optional error (e.g. token resolution failed).
    pub error: Option<String>,
}

/// Most rows the picker popup shows at once.
const MAX_ROWS: usize = 10;

/// Draws the centered connection-picker popup over `area`.
pub fn draw_contexts(frame: &mut Frame<'_>, area: Rect, model: &ContextsModel, theme: &Theme) {
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

    let title = if model.filter.is_empty() {
        "Contexts (type to filter)".to_owned()
    } else {
        format!("Contexts · /{}_", model.filter)
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(
            title,
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
    let [filter_row, message_row, list_row] = rows.as_ref() else {
        return;
    };

    frame.render_widget(Paragraph::new(contexts_filter(model, theme)), *filter_row);
    frame.render_widget(Paragraph::new(contexts_message(model, theme)), *message_row);

    let list_width = usize::from(list_row.width);
    let lines: Vec<Line<'_>> = if model.rows.is_empty() {
        vec![Line::from(Span::styled(
            "(no profiles configured)",
            Style::default().fg(theme.masked_fg),
        ))]
    } else {
        model
            .rows
            .iter()
            .take(MAX_ROWS)
            .enumerate()
            .map(|(index, row)| contexts_line(index, model.selected, row, theme, list_width))
            .collect()
    };
    frame.render_widget(Paragraph::new(lines), *list_row);
}

fn contexts_filter<'a>(model: &'a ContextsModel, theme: &Theme) -> Line<'a> {
    if model.filter.is_empty() {
        return Line::from(Span::styled(
            "/ filter",
            Style::default().fg(theme.masked_fg),
        ));
    }
    Line::from(vec![
        Span::styled(
            "/",
            Style::default()
                .fg(theme.title)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            model.filter.as_str(),
            Style::default().fg(theme.selected_fg),
        ),
        Span::styled("█", Style::default().fg(theme.title)),
    ])
}

fn contexts_message<'a>(model: &'a ContextsModel, theme: &Theme) -> Line<'a> {
    model.error.as_ref().map_or_else(
        || {
            Line::from(Span::styled(
                "enter switch │ esc cancel",
                Style::default().fg(theme.masked_fg),
            ))
        },
        |error| {
            Line::from(Span::styled(
                error.as_str(),
                Style::default().fg(theme.status_error),
            ))
        },
    )
}

fn contexts_line(
    index: usize,
    selected: usize,
    row: &ContextRow,
    theme: &Theme,
    width: usize,
) -> Line<'static> {
    let is_selected = index == selected;
    let name_fg = if is_selected {
        theme.selected_fg
    } else {
        theme.leaf_fg
    };
    let marker_fg = if is_selected {
        theme.selected_fg
    } else {
        theme.revealed_fg
    };
    let addr_fg = if is_selected {
        theme.selected_fg
    } else {
        theme.masked_fg
    };
    let marker = if row.current { "● " } else { "  " };
    let used = 2 + row.name.chars().count() + 2 + row.addr.chars().count();
    let pad = width.saturating_sub(used);
    let spans = vec![
        Span::styled(marker, Style::default().fg(marker_fg)),
        Span::styled(row.name.clone(), Style::default().fg(name_fg)),
        Span::styled(format!("  {}", row.addr), Style::default().fg(addr_fg)),
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

    fn render(model: &ContextsModel) -> String {
        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).expect("TestBackend");
        terminal
            .draw(|frame| {
                draw_contexts(frame, frame.area(), model, &Theme::default());
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

    fn rows() -> Vec<ContextRow> {
        vec![
            ContextRow {
                name: "dev".to_owned(),
                addr: "http://127.0.0.1:8200".to_owned(),
                current: true,
            },
            ContextRow {
                name: "prod".to_owned(),
                addr: "https://vault.example:8200".to_owned(),
                current: false,
            },
        ]
    }

    #[test]
    fn contexts_marks_the_current_profile() {
        // Given: a picker with a current profile and a second profile.
        let model = ContextsModel {
            rows: rows(),
            selected: 0,
            filter: String::new(),
            error: None,
        };

        // When: the picker is rendered.
        let output = render(&model);

        // Then: the current profile is marked and both addresses show.
        assert_snapshot!("contexts_current_marked", output);
        assert!(output.contains("● dev"));
        assert!(output.contains("https://vault.example:8200"));
    }

    #[test]
    fn contexts_shows_filter_buffer_in_title() {
        // Given: an active filter buffer.
        let model = ContextsModel {
            rows: vec![ContextRow {
                name: "prod".to_owned(),
                addr: "https://vault.example:8200".to_owned(),
                current: false,
            }],
            selected: 0,
            filter: "pr".to_owned(),
            error: None,
        };

        // When: the picker is rendered.
        let output = render(&model);

        // Then: the filter buffer appears in the title.
        assert_snapshot!("contexts_filtering", output);
        assert!(output.contains("Contexts · /pr_"));
    }

    #[test]
    fn contexts_shows_error_when_present() {
        // Given: a picker carrying a token-resolution error.
        let model = ContextsModel {
            rows: rows(),
            selected: 0,
            filter: String::new(),
            error: Some("token command failed".to_owned()),
        };

        // When: the picker is rendered.
        let output = render(&model);

        // Then: the error line replaces the hint.
        assert_snapshot!("contexts_error", output);
        assert!(output.contains("token command failed"));
    }

    #[test]
    fn contexts_shows_placeholder_when_empty() {
        // Given: no configured profiles.
        let model = ContextsModel {
            rows: Vec::new(),
            selected: 0,
            filter: String::new(),
            error: None,
        };

        // When: the picker is rendered.
        let output = render(&model);

        // Then: the empty-state line is shown.
        assert_snapshot!("contexts_empty", output);
        assert!(output.contains("(no profiles configured)"));
    }
}
