//! Secret key/value data renderer.

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};
use tui_textarea::TextArea;

use crate::{constants::MASK, theme::Theme};

/// Key row shown in the secret data list pane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRow {
    /// Secret key label rendered in the list.
    pub label: String,
}

/// Right-pane mode for the secret data view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataMode {
    /// Render only the key list.
    ListOnly,
    /// Render a read-only plaintext preview for the selected key.
    Preview {
        /// Secret key currently previewed.
        key: String,
        /// Plaintext value currently previewed.
        value: String,
    },
    /// Render an editor seeded with plaintext for the selected key.
    Edit {
        /// Secret key currently edited.
        key: String,
        /// Editor text seeded from the selected value.
        text: String,
    },
}

/// Render model for the secret data view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretDataModel {
    /// Secret name shown in the list pane title.
    pub secret_name: String,
    /// Secret engine mount containing the secret.
    pub engine: String,
    /// Vault `KV v2` secret version.
    pub version: u64,
    /// Metadata creation timestamp injected by the caller.
    pub created_time: String,
    /// Deterministically sorted key rows.
    pub keys: Vec<KeyRow>,
    /// Selected row offset.
    pub selected: usize,
    /// Current right-pane display mode.
    pub mode: DataMode,
}

/// Draws the secret data list and optional preview/editor pane.
pub fn draw_secret_data(frame: &mut Frame<'_>, area: Rect, model: &SecretDataModel, theme: &Theme) {
    match &model.mode {
        DataMode::ListOnly => draw_key_list(frame, area, model, theme),
        DataMode::Preview { key, value } => {
            let panes = split_with_details(area);
            let [left, right] = panes.as_ref() else {
                return;
            };
            draw_key_list(frame, *left, model, theme);
            draw_preview(frame, *right, key, value, theme);
        }
        DataMode::Edit { key, text } => {
            let panes = split_with_details(area);
            let [left, right] = panes.as_ref() else {
                return;
            };
            draw_key_list(frame, *left, model, theme);
            draw_editor(frame, *right, key, text, theme);
        }
    }
}

fn split_with_details(area: Rect) -> std::rc::Rc<[Rect]> {
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area)
}

fn draw_key_list(frame: &mut Frame<'_>, area: Rect, model: &SecretDataModel, theme: &Theme) {
    let rows = model.keys.iter().map(|row| {
        ListItem::new(Line::from(vec![
            Span::styled(row.label.as_str(), Style::default()),
            Span::raw(" "),
            Span::styled(MASK, Style::default().fg(theme.masked_fg)),
        ]))
    });
    let title = format!(
        "Secret: {}, Ver: {}, Created: {}",
        model.secret_name, model.version, model.created_time
    );
    let list = List::new(rows)
        .block(
            Block::default()
                .title(Line::from(title).style(Style::default().fg(theme.title)))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.border)),
        )
        .highlight_style(Style::default().fg(theme.selected_fg).bg(theme.selected_bg));
    let mut state = ListState::default().with_selected(Some(model.selected));
    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_preview(frame: &mut Frame<'_>, area: Rect, key: &str, value: &str, theme: &Theme) {
    let title = format!("Preview Mode: {key}");
    let paragraph = Paragraph::new(value)
        .style(Style::default().fg(theme.revealed_fg))
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .title(Line::from(title).style(Style::default().fg(theme.title)))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.border)),
        );
    frame.render_widget(paragraph, area);
}

fn draw_editor(frame: &mut Frame<'_>, area: Rect, key: &str, text: &str, theme: &Theme) {
    let title = format!("Edit Mode: {key}");
    let mut textarea = TextArea::new(vec![text.to_owned()]);
    textarea.set_style(Style::default().fg(theme.revealed_fg));
    textarea.set_block(
        Block::default()
            .title(Line::from(title).style(Style::default().fg(theme.title)))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.editor_border)),
    );
    frame.render_widget(&textarea, area);
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "snapshot test helper follows the contract supplied by the task"
)]
mod tests {
    use ratatui::{Terminal, backend::TestBackend, style::Color};

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

    fn fixture(mode: DataMode) -> SecretDataModel {
        SecretDataModel {
            secret_name: "payments/api".to_owned(),
            engine: "kv".to_owned(),
            version: 7,
            created_time: "2026-10-13T10:11:12Z".to_owned(),
            keys: vec![
                KeyRow {
                    label: "api_key".to_owned(),
                },
                KeyRow {
                    label: "password".to_owned(),
                },
                KeyRow {
                    label: "username".to_owned(),
                },
            ],
            selected: 1,
            mode,
        }
    }

    #[test]
    fn draw_secret_data_shows_masked_list_when_mode_is_list_only() {
        // Given: three deterministic keys and no right-pane mode.
        let model = fixture(DataMode::ListOnly);
        let theme = Theme::default();

        // When: the secret data view is rendered into the terminal buffer.
        let actual = render(120, 30, |frame| {
            draw_secret_data(frame, frame.area(), &model, &theme);
        });

        // Then: the list title and masked key rows are stable.
        insta::assert_snapshot!(actual);
    }

    #[test]
    fn draw_secret_data_shows_multiline_value_when_mode_is_preview() {
        // Given: a preview mode with a multiline secret value.
        let model = fixture(DataMode::Preview {
            key: "password".to_owned(),
            value: "line one\nline two".to_owned(),
        });
        let theme = Theme::default();

        // When: the secret data view is rendered into the terminal buffer.
        let actual = render(120, 30, |frame| {
            draw_secret_data(frame, frame.area(), &model, &theme);
        });

        // Then: the preview pane contains the raw multiline value.
        insta::assert_snapshot!(actual);
    }

    #[test]
    fn draw_secret_data_shows_seeded_text_when_mode_is_edit() {
        // Given: an edit mode with existing secret text.
        let model = fixture(DataMode::Edit {
            key: "password".to_owned(),
            text: "editable-secret".to_owned(),
        });
        let theme = Theme::default();

        // When: the secret data view is rendered into the terminal buffer.
        let actual = render(120, 30, |frame| {
            draw_secret_data(frame, frame.area(), &model, &theme);
        });

        // Then: the editor pane is seeded with the current secret text.
        insta::assert_snapshot!(actual);
    }

    #[test]
    fn draw_secret_data_marks_selected_row_with_theme_background() {
        // Given: a selected row and a distinctive selection background.
        let model = fixture(DataMode::ListOnly);
        let theme = Theme {
            selected_bg: Color::Blue,
            ..Theme::default()
        };
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).expect("TestBackend");

        // When: the secret data view is rendered into the terminal buffer.
        terminal
            .draw(|frame| draw_secret_data(frame, frame.area(), &model, &theme))
            .expect("draw");

        // Then: the selected row cell uses the theme selection background.
        let style = terminal
            .backend()
            .buffer()
            .cell((1, 2))
            .map(ratatui::buffer::Cell::style)
            .expect("selected row cell");
        assert_eq!(style.bg, Some(theme.selected_bg));
    }
}
