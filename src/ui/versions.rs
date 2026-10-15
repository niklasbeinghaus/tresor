//! Secret version history renderer.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use super::row::row_line;
use super::secret_data::{SecretDataModel, draw_secret_data};
use crate::theme::Theme;

/// One rendered version-history row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionRow {
    /// Version number.
    pub version: u64,
    /// RFC3339 creation timestamp.
    pub created_time: String,
    /// RFC3339 deletion timestamp, when soft-deleted.
    pub deletion_time: Option<String>,
    /// Whether this version is permanently destroyed.
    pub destroyed: bool,
    /// Whether this row is the latest version.
    pub is_current: bool,
}

/// Render model for the version-history pane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionsModel {
    /// Secret path label for the list title.
    pub secret_name: String,
    /// Engine mount label.
    pub engine: String,
    /// Version rows sorted newest-first.
    pub rows: Vec<VersionRow>,
    /// Selected row index.
    pub selected: usize,
    /// Optional version preview rendered by the secret-data renderer.
    pub preview: Option<SecretDataModel>,
}

/// Draws the version list and optional right-pane version preview.
pub fn draw_versions(frame: &mut Frame<'_>, area: Rect, model: &VersionsModel, theme: &Theme) {
    if let Some(preview) = &model.preview {
        let panes = split_with_details(area);
        let [left, right] = panes.as_ref() else {
            return;
        };
        draw_versions_list(frame, *left, model, theme);
        draw_secret_data(frame, *right, preview, theme);
        return;
    }
    draw_versions_list(frame, area, model, theme);
}

fn draw_versions_list(frame: &mut Frame<'_>, area: Rect, model: &VersionsModel, theme: &Theme) {
    let title = format!("Versions: {}", model.secret_name);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(title, Style::default().fg(theme.title)));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let selected = selected_index(model.selected, model.rows.len());
    let visible_rows = usize::from(inner.height);
    let lines: Vec<Line<'_>> = model
        .rows
        .iter()
        .take(visible_rows)
        .enumerate()
        .map(|(index, row)| version_line(index, selected, row, theme, inner.width))
        .collect();
    frame.render_widget(Paragraph::new(lines), inner);
}

fn split_with_details(area: Rect) -> std::rc::Rc<[Rect]> {
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area)
}

fn selected_index(selected: usize, len: usize) -> Option<usize> {
    len.checked_sub(1).map(|last| selected.min(last))
}

fn version_line(
    index: usize,
    selected: Option<usize>,
    row: &VersionRow,
    theme: &Theme,
    width: u16,
) -> Line<'static> {
    let mut state_parts: Vec<String> = Vec::new();
    if row.is_current {
        state_parts.push("current".to_owned());
    }
    if let Some(deleted_at) = &row.deletion_time {
        state_parts.push(format!("deleted {deleted_at}"));
    }
    if row.destroyed {
        state_parts.push("destroyed".to_owned());
    }
    let state = if state_parts.is_empty() {
        String::new()
    } else {
        format!(" [{}]", state_parts.join(","))
    };
    let label = format!("v{}  {}{}", row.version, row.created_time, state);
    row_line(index, selected, &label, theme.leaf_fg, theme, width)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "snapshot test helper follows the existing test pattern"
)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;
    use crate::ui::secret_data::{DataMode, KeyRow};

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

    fn model(preview: Option<SecretDataModel>) -> VersionsModel {
        VersionsModel {
            secret_name: "apps/web/db-creds".to_owned(),
            engine: "secret".to_owned(),
            rows: vec![
                VersionRow {
                    version: 7,
                    created_time: "2026-10-13T10:00:00Z".to_owned(),
                    deletion_time: None,
                    destroyed: false,
                    is_current: true,
                },
                VersionRow {
                    version: 6,
                    created_time: "2026-10-12T10:00:00Z".to_owned(),
                    deletion_time: Some("2026-10-12T11:00:00Z".to_owned()),
                    destroyed: false,
                    is_current: false,
                },
                VersionRow {
                    version: 5,
                    created_time: "2026-10-11T10:00:00Z".to_owned(),
                    deletion_time: None,
                    destroyed: true,
                    is_current: false,
                },
            ],
            selected: 1,
            preview,
        }
    }

    fn preview_model() -> SecretDataModel {
        SecretDataModel {
            secret_name: "apps/web/db-creds".to_owned(),
            engine: "secret".to_owned(),
            version: 6,
            created_time: "2026-10-12T10:00:00Z".to_owned(),
            keys: vec![
                KeyRow {
                    label: "password".to_owned(),
                },
                KeyRow {
                    label: "username".to_owned(),
                },
            ],
            selected: 0,
            mode: DataMode::Preview {
                key: "password".to_owned(),
                value: "pw-v6".to_owned(),
            },
            read_only: true,
        }
    }

    #[test]
    fn draw_versions_shows_columns_current_deleted_destroyed() {
        let model = model(None);
        let theme = Theme::default();

        let actual = render(100, 20, |frame| {
            draw_versions(frame, frame.area(), &model, &theme);
        });

        insta::assert_snapshot!(actual);
    }

    #[test]
    fn draw_versions_with_preview_reuses_secret_data_renderer() {
        let model = model(Some(preview_model()));
        let theme = Theme::default();

        let actual = render(120, 30, |frame| {
            draw_versions(frame, frame.area(), &model, &theme);
        });

        insta::assert_snapshot!(actual);
    }
}
