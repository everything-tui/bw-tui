//! Shared form field widgets.

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use ratatui::style::Color;

const ACCENT: Color = Color::Rgb(175, 82, 222);
const FG: Color = Color::White;
const MUTED: Color = Color::DarkGray;

pub fn draw_form_field(
    frame: &mut Frame,
    area: Rect,
    label: &str,
    value: &str,
    focused: bool,
    secret: bool,
) {
    draw_form_field_with_hint(frame, area, label, value, focused, secret, "");
}

/// Like [`draw_form_field`], with a key hint right-aligned in the top border
/// (e.g. `Ctrl+g generate` on a password field).
pub fn draw_form_field_with_hint(
    frame: &mut Frame,
    area: Rect,
    label: &str,
    value: &str,
    focused: bool,
    secret: bool,
    hint: &str,
) {
    let border = if focused {
        Style::default().fg(ACCENT)
    } else {
        Style::default().fg(MUTED)
    };
    let title_style = if focused {
        Style::default().fg(FG).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(MUTED)
    };
    let mut block = Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .title(Span::styled(format!(" {label} "), title_style));
    if !hint.is_empty() {
        let hint_style = if focused {
            Style::default().fg(ACCENT)
        } else {
            Style::default().fg(MUTED)
        };
        block =
            block.title(Line::from(Span::styled(format!(" {hint} "), hint_style)).right_aligned());
    }
    let display = if secret && !value.is_empty() {
        let masked = "•".repeat(value.chars().count().min(48));
        if focused {
            format!("{masked}▌")
        } else {
            masked
        }
    } else if value.is_empty() && focused {
        "▌".to_string()
    } else if focused {
        format!("{value}▌")
    } else {
        value.to_string()
    };
    frame.render_widget(
        Paragraph::new(display)
            .style(Style::default().fg(FG))
            .block(block),
        area,
    );
}
