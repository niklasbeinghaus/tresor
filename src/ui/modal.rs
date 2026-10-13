//! Vault configuration popup renderer.

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::Line,
    widgets::{Block, Borders, Clear, Paragraph},
};

use crate::theme::Theme;

/// Input field focused inside the vault configuration modal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModalField {
    /// Vault server address field.
    Addr,
    /// Vault authentication token field.
    Token,
}

/// Render model for the vault configuration modal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModalModel {
    /// Vault server address typed by the user.
    pub addr: String,
    /// Plaintext vault token typed by the user; rendered masked.
    pub token: String,
    /// Currently focused input field.
    pub focus: ModalField,
    /// Optional validation or connection error.
    pub error: Option<String>,
}

/// Draws the centered vault configuration popup.
pub fn draw_modal(frame: &mut Frame<'_>, area: Rect, model: &ModalModel, theme: &Theme) {
    let popup = centered_rect(60, 60, area);
    let block = Block::default()
        .title(Line::from("Vault Configuration").style(Style::default().fg(theme.title)))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border));
    let inner = block.inner(popup);

    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(inner);
    let [
        addr_label,
        addr_input,
        token_label,
        token_input,
        message,
        hint,
    ] = rows.as_ref()
    else {
        return;
    };

    frame.render_widget(label("Vault Address", theme), *addr_label);
    frame.render_widget(
        input(&model.addr, model.focus == ModalField::Addr, theme),
        *addr_input,
    );
    frame.render_widget(label("Vault Token", theme), *token_label);
    frame.render_widget(
        input(
            &mask_token(&model.token),
            model.focus == ModalField::Token,
            theme,
        ),
        *token_input,
    );

    if let Some(error) = &model.error {
        frame.render_widget(
            Paragraph::new(error.as_str()).style(Style::default().fg(theme.status_error)),
            *message,
        );
    }

    frame.render_widget(
        Paragraph::new("Enter to connect · Esc to quit")
            .style(Style::default().fg(theme.status_info)),
        *hint,
    );
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    let [_, middle, _] = vertical.as_ref() else {
        return area;
    };
    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(*middle);
    let [_, center, _] = horizontal.as_ref() else {
        return *middle;
    };
    *center
}

fn label(text: &'static str, theme: &Theme) -> Paragraph<'static> {
    Paragraph::new(text).style(Style::default().fg(theme.title))
}

fn input<'a>(text: &'a str, focused: bool, theme: &Theme) -> Paragraph<'a> {
    let style = if focused {
        Style::default().fg(theme.selected_fg).bg(theme.selected_bg)
    } else {
        Style::default()
    };
    Paragraph::new(text).style(style)
}

fn mask_token(token: &str) -> String {
    "*".repeat(token.chars().count())
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "snapshot test helper follows the contract supplied by the task"
)]
mod tests {
    use ratatui::{Terminal, backend::TestBackend};

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

    #[test]
    fn draw_modal_shows_addr_focus_when_default_model() {
        // Given: a vault configuration modal with focus on address.
        let model = ModalModel {
            addr: "https://vault.example.com".to_owned(),
            token: String::new(),
            focus: ModalField::Addr,
            error: None,
        };
        let theme = Theme::default();

        // When: the modal is rendered into the terminal buffer.
        let actual = render(120, 30, |frame| {
            draw_modal(frame, frame.area(), &model, &theme);
        });

        // Then: the centered form and focused address input are stable.
        insta::assert_snapshot!(actual);
    }

    #[test]
    fn draw_modal_masks_token_when_token_field_is_filled() {
        // Given: a vault configuration modal with a plaintext token in the model.
        let model = ModalModel {
            addr: "http://127.0.0.1:8200".to_owned(),
            token: "s.123456789".to_owned(),
            focus: ModalField::Token,
            error: None,
        };
        let theme = Theme::default();

        // When: the modal is rendered into the terminal buffer.
        let actual = render(120, 30, |frame| {
            draw_modal(frame, frame.area(), &model, &theme);
        });

        // Then: the token row shows only mask characters.
        insta::assert_snapshot!(actual);
    }

    #[test]
    fn draw_modal_shows_error_when_error_is_present() {
        // Given: a vault configuration modal with a connection error.
        let model = ModalModel {
            addr: "https://vault.example.com".to_owned(),
            token: "topsecret".to_owned(),
            focus: ModalField::Addr,
            error: Some("permission denied".to_owned()),
        };
        let theme = Theme::default();

        // When: the modal is rendered into the terminal buffer.
        let actual = render(120, 30, |frame| {
            draw_modal(frame, frame.area(), &model, &theme);
        });

        // Then: the error line is included below the inputs.
        insta::assert_snapshot!(actual);
    }
}
