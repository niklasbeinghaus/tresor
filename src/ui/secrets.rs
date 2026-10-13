//! Hierarchical secret browser renderer.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use super::row::row_line;
use crate::model::SecretEntry;
use crate::path::SecretPath;
use crate::theme::Theme;

/// Data rendered by the hierarchical secret browser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretsModel {
    /// Active secret engine name.
    pub engine: String,
    /// Current directory path inside the engine.
    pub path: SecretPath,
    /// Directory and leaf entries for the current path.
    pub entries: Vec<SecretEntry>,
    /// Selected entry index.
    pub selected: usize,
}

/// Render the hierarchical secret browser.
pub fn draw_secrets(frame: &mut Frame<'_>, area: Rect, model: &SecretsModel, theme: &Theme) {
    let title = format!("Secret Engine: {}", model.engine);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(title, Style::default().fg(theme.title)));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).split(inner);
    let [breadcrumb_row, list_row] = rows.as_ref() else {
        return;
    };
    frame.render_widget(
        Paragraph::new(format!("path: /{}", model.path.as_str())),
        *breadcrumb_row,
    );

    let selected = selected_index(model.selected, model.entries.len());
    let visible_rows = usize::from(list_row.height);
    let lines: Vec<Line<'_>> = model
        .entries
        .iter()
        .take(visible_rows)
        .enumerate()
        .map(|(index, entry)| secret_line(index, selected, entry, theme, list_row.width))
        .collect();
    frame.render_widget(Paragraph::new(lines), *list_row);
}

/// Sort entries as directories first, then leaves, alphabetically within each group.
pub fn sort_entries(entries: &mut [SecretEntry]) {
    entries.sort_by(|left, right| match (left.is_dir, right.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        (true, true) | (false, false) => left.name.as_str().cmp(right.name.as_str()),
    });
}

fn secret_line(
    index: usize,
    selected: Option<usize>,
    entry: &SecretEntry,
    theme: &Theme,
    width: u16,
) -> Line<'static> {
    let fg = if entry.is_dir {
        theme.dir_fg
    } else {
        theme.leaf_fg
    };
    row_line(index, selected, entry.name.as_str(), fg, theme, width)
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

    fn mixed_entries() -> Vec<SecretEntry> {
        vec![
            SecretEntry::leaf("token"),
            SecretEntry::dir("apps/"),
            SecretEntry::leaf("api-key"),
            SecretEntry::dir("infra/"),
        ]
    }

    #[test]
    fn sort_entries_groups_dirs_before_leaves() {
        let mut entries = mixed_entries();
        sort_entries(&mut entries);
        let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
        assert_eq!(names, vec!["apps/", "infra/", "api-key", "token"]);
    }

    #[test]
    fn secrets_render_sorted_mixed_entries() {
        let mut entries = mixed_entries();
        sort_entries(&mut entries);
        let model = SecretsModel {
            engine: "secret".into(),
            path: SecretPath::new(""),
            entries,
            selected: 1,
        };
        assert_snapshot!(
            "secrets_sorted_mixed_entries",
            render(48, 8, |f| draw_secrets(
                f,
                Rect::new(0, 0, 48, 8),
                &model,
                &Theme::default()
            ))
        );
    }

    #[test]
    fn secrets_dir_row_uses_dir_color() {
        let theme = Theme::default();
        let model = SecretsModel {
            engine: "secret".into(),
            path: SecretPath::new(""),
            entries: vec![SecretEntry::dir("apps/"), SecretEntry::leaf("token")],
            selected: 1,
        };
        let backend = TestBackend::new(32, 6);
        let mut terminal = Terminal::new(backend).expect("TestBackend");
        terminal
            .draw(|f| draw_secrets(f, Rect::new(0, 0, 32, 6), &model, &theme))
            .expect("draw");
        let buffer = terminal.backend().buffer();
        let style = buffer.cell((1, 2)).map(ratatui::buffer::Cell::style);
        assert_eq!(style.map(|style| style.fg), Some(Some(theme.dir_fg)));
    }

    #[test]
    fn secrets_render_nested_path_breadcrumb() {
        let model = SecretsModel {
            engine: "kv".into(),
            path: SecretPath::new("team/platform/"),
            entries: vec![SecretEntry::leaf("token")],
            selected: 0,
        };
        assert_snapshot!(
            "secrets_nested_path",
            render(48, 6, |f| draw_secrets(
                f,
                Rect::new(0, 0, 48, 6),
                &model,
                &Theme::default()
            ))
        );
    }

    #[test]
    fn secrets_empty_list() {
        let model = SecretsModel {
            engine: "secret".into(),
            path: SecretPath::new(""),
            entries: Vec::new(),
            selected: 0,
        };
        assert_snapshot!(
            "secrets_empty",
            render(40, 5, |f| draw_secrets(
                f,
                Rect::new(0, 0, 40, 5),
                &model,
                &Theme::default()
            ))
        );
    }
}
