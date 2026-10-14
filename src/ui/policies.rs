//! ACL policies browser renderer.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use super::row::row_line;
use crate::constants::titles;
use crate::model::PolicyEntry;
use crate::theme::Theme;

/// Right pane preview state for the policies page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyPreview {
    /// No policies are available.
    Empty,
    /// A selected policy is loading.
    Loading {
        /// Selected policy name.
        name: String,
    },
    /// A selected policy was loaded.
    Loaded {
        /// Selected policy name.
        name: String,
        /// Loaded policy text.
        policy: String,
    },
    /// Loading the selected policy failed.
    Error {
        /// Selected policy name.
        name: String,
        /// User-facing load failure.
        message: String,
    },
}

/// Data rendered by the policies page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoliciesModel {
    /// Policy list entries.
    pub entries: Vec<PolicyEntry>,
    /// Selected row index.
    pub selected: usize,
    /// Right pane preview.
    pub preview: PolicyPreview,
}

/// Draws the policies page with list + read-only preview split.
pub fn draw_policies(frame: &mut Frame<'_>, area: Rect, model: &PoliciesModel, theme: &Theme) {
    let panes =
        Layout::horizontal([Constraint::Percentage(35), Constraint::Percentage(65)]).split(area);
    let [left, right] = panes.as_ref() else {
        return;
    };

    draw_policies_list(frame, *left, model, theme);
    draw_preview(frame, *right, &model.preview, theme);
}

fn draw_policies_list(frame: &mut Frame<'_>, area: Rect, model: &PoliciesModel, theme: &Theme) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(
            titles::POLICIES,
            Style::default().fg(theme.title),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let selected = model
        .entries
        .len()
        .checked_sub(1)
        .map(|last| model.selected.min(last));
    let lines: Vec<Line<'_>> = model
        .entries
        .iter()
        .take(usize::from(inner.height))
        .enumerate()
        .map(|(index, entry)| {
            row_line(
                index,
                selected,
                &entry.name,
                theme.leaf_fg,
                theme,
                inner.width,
            )
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), inner);
}

fn draw_preview(frame: &mut Frame<'_>, area: Rect, preview: &PolicyPreview, theme: &Theme) {
    let (title, content, color) = match preview {
        PolicyPreview::Empty => (
            String::from("Policy"),
            "No policies available".to_owned(),
            theme.masked_fg,
        ),
        PolicyPreview::Loading { name } => (
            format!("Policy: {name}"),
            "Loading...".to_owned(),
            theme.masked_fg,
        ),
        PolicyPreview::Loaded { name, policy } => {
            (format!("Policy: {name}"), policy.clone(), theme.revealed_fg)
        }
        PolicyPreview::Error { name, message } => (
            format!("Policy: {name}"),
            message.clone(),
            theme.status_error,
        ),
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(title, Style::default().fg(theme.title)));
    let paragraph = Paragraph::new(content)
        .style(Style::default().fg(color))
        .wrap(Wrap { trim: false })
        .block(block);
    frame.render_widget(paragraph, area);
}

#[cfg(test)]
mod tests {
    use insta::assert_snapshot;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::{PoliciesModel, PolicyPreview, draw_policies};
    use crate::model::PolicyEntry;
    use crate::theme::Theme;

    fn render(model: &PoliciesModel) -> String {
        let backend = TestBackend::new(100, 20);
        let mut terminal = Terminal::new(backend).expect("TestBackend");
        terminal
            .draw(|frame| draw_policies(frame, frame.area(), model, &Theme::default()))
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
    fn policies_view_empty_preview_snapshot() {
        let output = render(&PoliciesModel {
            entries: vec![PolicyEntry {
                name: "default".to_owned(),
            }],
            selected: 0,
            preview: PolicyPreview::Empty,
        });
        assert_snapshot!("policies_empty_preview", output);
    }

    #[test]
    fn policies_view_loaded_preview_snapshot() {
        let output = render(&PoliciesModel {
            entries: vec![
                PolicyEntry {
                    name: "default".to_owned(),
                },
                PolicyEntry {
                    name: "team".to_owned(),
                },
            ],
            selected: 1,
            preview: PolicyPreview::Loaded {
                name: "team".to_owned(),
                policy: "path \"secret/data/team/*\" {\n  capabilities = [\"read\"]\n}".to_owned(),
            },
        });
        assert_snapshot!("policies_loaded_preview", output);
    }

    #[test]
    fn policies_view_loading_preview_snapshot() {
        let output = render(&PoliciesModel {
            entries: vec![PolicyEntry {
                name: "default".to_owned(),
            }],
            selected: 0,
            preview: PolicyPreview::Loading {
                name: "default".to_owned(),
            },
        });
        assert_snapshot!("policies_loading_preview", output);
    }
}
