//! Shared form field widgets.

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::Span;
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
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .title(Span::styled(format!(" {label} "), title_style));
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
