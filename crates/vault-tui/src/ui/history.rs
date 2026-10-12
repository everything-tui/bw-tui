//! Password history overlay (H).

use ratatui::layout::Alignment;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::App;
use crate::ui::layout::center_fixed;

const ACCENT: Color = Color::Rgb(175, 82, 222);
const MUTED: Color = Color::DarkGray;
const FG: Color = Color::White;

pub fn draw_password_history(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let popup = center_fixed(58, 14, area);
    frame.render_widget(Clear, popup);

    let title = app
        .selected_decrypted()
        .map(|i| format!(" Password history — {} ", i.name))
        .unwrap_or_else(|| " Password history ".into());

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            title,
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            " Esc close ",
            Style::default().fg(MUTED),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let Some(item) = app.selected_decrypted() else {
        frame.render_widget(
            Paragraph::new("No item selected").alignment(Alignment::Center),
            inner,
        );
        return;
    };

    if item.password_history.is_empty() {
        frame.render_widget(
            Paragraph::new("No previous passwords recorded for this item.")
                .style(Style::default().fg(MUTED))
                .alignment(Alignment::Center)
                .wrap(Wrap { trim: true }),
            inner,
        );
        return;
    }

    let mut lines = Vec::new();
    for (i, entry) in item.password_history.iter().enumerate() {
        let when = entry
            .last_used_date
            .as_deref()
            .unwrap_or("unknown date");
        let pw = if app.reveal_secrets {
            entry.password.as_str()
        } else {
            "••••••••"
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{}  ", i + 1), Style::default().fg(MUTED)),
            Span::styled(pw, Style::default().fg(FG)),
            Span::styled(format!("  ({when})"), Style::default().fg(MUTED)),
        ]));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}
