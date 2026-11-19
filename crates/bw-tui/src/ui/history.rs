//! Password history overlay (H).

use ratatui::layout::Alignment;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use crate::app::App;
use crate::ui::chrome;
use crate::ui::layout::center_fixed;
use crate::ui::theme::pal;

pub fn draw_password_history(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let popup = center_fixed(58, 14, area);

    let title = app
        .selected_decrypted()
        .map(|i| format!(" Password history — {} ", i.name))
        .unwrap_or_else(|| " Password history ".into());

    let inner = chrome::modal(frame, popup, title, " Esc close ");

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
                .style(Style::default().fg(pal::muted()))
                .alignment(Alignment::Center)
                .wrap(Wrap { trim: true }),
            inner,
        );
        return;
    }

    let mut lines = Vec::new();
    for (i, entry) in item.password_history.iter().enumerate() {
        let when = entry.last_used_date.as_deref().unwrap_or("unknown date");
        let pw = if app.reveal_secrets {
            entry.password.as_str()
        } else {
            "••••••••"
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{}  ", i + 1), Style::default().fg(pal::muted())),
            Span::styled(pw, Style::default().fg(pal::text())),
            Span::styled(format!("  ({when})"), Style::default().fg(pal::muted())),
        ]));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}
