//! Help overlay modal — driven by the canonical keymap table.

use ratatui::layout::{Alignment, Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use crate::keymap::BINDINGS;
use crate::ui::layout::center_fixed;
use crate::ui::theme;

pub fn draw_help(frame: &mut Frame) {
    let t = theme();
    let area = frame.area();
    let height = (BINDINGS.len() as u16)
        .saturating_add(6)
        .min(area.height.saturating_sub(2));
    let popup = center_fixed(72, height, area);

    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(t.focused_border())
        .title(Span::styled(" Help ", t.title()))
        .title_bottom(Span::styled(" Esc / ? / q to close ", t.muted_style()));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);

    let lines: Vec<Line> = BINDINGS
        .iter()
        .map(|b| {
            Line::from(vec![
                Span::styled(
                    format!("  {:<14}", b.keys),
                    Style::default().fg(t.accent).add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("{} · {}", b.action, b.context), t.normal()),
            ])
        })
        .chain(std::iter::once(Line::from("")))
        .chain(std::iter::once(Line::from(Span::styled(
            "Panes collapse: detail <80 cols · folders <60 cols",
            t.muted_style(),
        ))))
        .collect();

    frame.render_widget(Paragraph::new(lines), chunks[0]);
    frame.render_widget(
        Paragraph::new("bitwarden-tui · Vaultwarden client")
            .style(t.muted_style())
            .alignment(Alignment::Center),
        chunks[1],
    );
}
